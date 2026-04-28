// Copyright © 2026 Roberto Chiofalo.

//! Integration tests for the `rustgate-mqtt` Prometheus metrics
//! surface added under issue #771.
//!
//! These tests pin contract surfaces that unit tests cannot (the
//! crate's `metrics::init` registers metrics into the global default
//! registry, and once-per-process registration semantics are only
//! visible from outside the unit-test crate boundary). Each test runs
//! in isolation and asserts a counter / gauge transition rather than
//! an absolute value, so parallel test runs do not interfere.

#![cfg(feature = "metrics")]
#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use rustgate_mqtt::metrics;

/// `init()` must succeed exactly once per process; after that the
/// accessors must continue to return the registered metrics rather
/// than installing a fresh fallback. Pin the idempotency contract so
/// a second `init()` call from a future test or operator-installed
/// hook surfaces the duplicate-registration error rather than
/// silently shadowing the live counters.
#[test]
fn init_returns_error_on_duplicate_registration() {
    // First call may succeed or land on an already-registered slot
    // (e.g. another integration test may have called it first under
    // nextest's process isolation, but unit tests in the parent crate
    // can also drive registration through the `OnceLock` slot). The
    // contract this test pins is that a *second* call after success
    // surfaces the error rather than overwriting silently.
    let first = metrics::init();
    let second = metrics::init();
    if first.is_ok() {
        assert!(
            second.is_err(),
            "second init() must error after a successful first call",
        );
    }
}

/// The active-sessions gauge supports the inc/dec lifecycle the
/// session handler relies on. Pin the round-trip so a regression that
/// switches the type to `IntCounter` (which has no `dec`) fails here.
#[test]
fn active_sessions_gauge_inc_dec_round_trip() {
    let g = metrics::active_sessions();
    let before = g.get();
    g.inc();
    assert_eq!(g.get(), before + 1);
    g.dec();
    assert_eq!(g.get(), before);
}

/// Per-QoS publish counters increment independently. Pin label
/// isolation so a regression that wired one label into the other
/// surfaces here.
#[test]
fn publish_total_qos_label_isolation() {
    let counter = metrics::publish_total();
    let q0 = counter
        .get_metric_with_label_values(&["0"])
        .expect("qos=0 label");
    let q2 = counter
        .get_metric_with_label_values(&["2"])
        .expect("qos=2 label");
    let q0_before = q0.get();
    let q2_before = q2.get();

    q2.inc();

    assert_eq!(q2.get(), q2_before + 1, "qos=2 must move");
    assert_eq!(
        q0.get(),
        q0_before,
        "qos=0 MUST NOT move when qos=2 increments — label isolation",
    );
}

/// The will-messages counter increments cleanly and is independent of
/// `active_sessions`. Pin both contracts so a regression that aliased
/// the two surfaces here.
#[test]
fn will_messages_independent_of_active_sessions_gauge() {
    let will = metrics::will_messages_total();
    let active = metrics::active_sessions();

    let will_before = will.get();
    let active_before = active.get();

    will.inc();

    assert_eq!(will.get(), will_before + 1);
    assert_eq!(active.get(), active_before);
}
