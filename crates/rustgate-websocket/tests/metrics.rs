// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the `rustgate-websocket` Prometheus metrics
//! surface added under issue #771.
//!
//! Each test pins one contract: the `init()` idempotency rule, the
//! `active_connections` inc/dec round-trip, the per-direction message
//! counter label isolation, and the bounded compression / subprotocol
//! result vocabulary.

#![cfg(feature = "metrics")]
#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use rustgate_websocket::metrics;

/// `init()` must surface a duplicate-registration error after a
/// successful call rather than silently shadowing the live metrics.
#[test]
fn init_returns_error_on_duplicate_registration() {
    let first = metrics::init();
    let second = metrics::init();
    if first.is_ok() {
        assert!(
            second.is_err(),
            "second init() must error after a successful first call",
        );
    }
}

/// The active-connections gauge supports the inc/dec lifecycle the
/// session handler relies on.
#[test]
fn active_connections_gauge_inc_dec_round_trip() {
    let g = metrics::active_connections();
    let before = g.get();
    g.inc();
    assert_eq!(g.get(), before + 1);
    g.dec();
    assert_eq!(g.get(), before);
}

/// Per-direction message counter labels move independently.
#[test]
fn messages_total_direction_label_isolation() {
    let counter = metrics::messages_total();
    let inbound = counter
        .get_metric_with_label_values(&["in"])
        .expect("in label");
    let outbound = counter
        .get_metric_with_label_values(&["out"])
        .expect("out label");
    let in_before = inbound.get();
    let out_before = outbound.get();

    inbound.inc();

    assert_eq!(inbound.get(), in_before + 1);
    assert_eq!(
        outbound.get(),
        out_before,
        "out direction MUST NOT move when in increments — label isolation",
    );
}

/// The compression-result vocabulary is bounded at the call site.
/// Each documented value must be queryable as a child counter.
#[test]
fn compression_negotiated_vocabulary_is_bounded() {
    let counter = metrics::compression_negotiated_total();
    for outcome in &["enabled", "disabled", "not_offered"] {
        counter
            .get_metric_with_label_values(&[outcome])
            .unwrap_or_else(|_| panic!("documented vocabulary `{outcome}` must be queryable"));
    }
}

/// Subprotocol counter accepts both a real subprotocol token and the
/// reserved `none` token used for handshakes that did not negotiate.
#[test]
fn subprotocol_selected_accepts_known_tokens() {
    let counter = metrics::subprotocol_selected_total();
    counter
        .get_metric_with_label_values(&["none"])
        .expect("the `none` token must be queryable");
    counter
        .get_metric_with_label_values(&["v2.tak"])
        .expect("any operator-configured token shape must be queryable");
}
