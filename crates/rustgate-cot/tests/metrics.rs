// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the `rustgate-cot` Prometheus metrics surface
//! added under issue #771.
//!
//! Each test pins one externally-observable contract: a successful
//! `parse` increments the `ok` counter, a malformed payload increments
//! the `err` counter, and the parse-latency histogram observes a
//! sample for both paths. The `OnceLock`-backed accessors do not
//! require the registry to be wired through `metrics::init()` — that
//! is the unit test's job — so the integration test exercises the
//! public `parse` API verbatim.

#![cfg(feature = "metrics")]
#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use rustgate_cot::{metrics, parse};

/// A successful `parse` call drives the `ok` counter and observes a
/// sample on the latency histogram.
#[test]
fn parse_success_increments_ok_counter_and_observes_histogram() {
    let xml = br#"<event uid="ALPHA-1" type="a-f-G" time="2026-01-01T00:00:00.000Z" start="2026-01-01T00:00:00.000Z" stale="2026-01-01T00:05:00.000Z"><point lat="0.0" lon="0.0" hae="0.0"/></event>"#;

    let counter = metrics::parse_total();
    let ok_child = counter
        .get_metric_with_label_values(&["ok"])
        .expect("ok label");
    let ok_before = ok_child.get();

    let hist = metrics::parse_seconds();
    let count_before = hist.get_sample_count();

    parse(xml).expect("parse must succeed for well-formed CoT XML");

    assert_eq!(
        ok_child.get(),
        ok_before + 1,
        "ok counter must increment exactly once per successful parse",
    );
    assert!(
        hist.get_sample_count() > count_before,
        "histogram must observe at least one sample after a parse call",
    );
}

/// A malformed payload drives the `err` counter without polluting the
/// `ok` counter, and still observes a histogram sample so latency is
/// visible regardless of outcome.
#[test]
fn parse_failure_increments_err_counter_independently_of_ok() {
    let counter = metrics::parse_total();
    let ok_child = counter
        .get_metric_with_label_values(&["ok"])
        .expect("ok label");
    let err_child = counter
        .get_metric_with_label_values(&["err"])
        .expect("err label");
    let ok_before = ok_child.get();
    let err_before = err_child.get();

    let hist = metrics::parse_seconds();
    let count_before = hist.get_sample_count();

    // No <event uid=…> — `parse` must reject this with `MissingAttribute`.
    let bad_xml = b"<event/>";
    assert!(parse(bad_xml).is_err());

    assert_eq!(
        err_child.get(),
        err_before + 1,
        "err counter must increment exactly once per failed parse",
    );
    assert_eq!(
        ok_child.get(),
        ok_before,
        "ok counter MUST NOT move when the parse failed — label isolation",
    );
    assert!(
        hist.get_sample_count() > count_before,
        "histogram must observe a sample for the failed path too",
    );
}
