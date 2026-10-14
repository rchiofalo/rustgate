// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests for the `rustgate-proto` Prometheus metrics
//! surface added under issue #771.
//!
//! Each test pins one externally-observable contract: a successful
//! `xml_to_proto` / `proto_to_xml` increments the matching `ok`
//! counter, a malformed payload increments the `err` counter, and
//! both paths observe a sample on the per-`kind` latency histogram.

#![cfg(feature = "metrics")]
#![allow(clippy::panic, clippy::unwrap_used, unused_results)]

use rustgate_proto::{metrics, proto_to_xml, xml_to_proto};

/// `xml_to_proto` success increments the `xml_to_proto, ok` counter
/// and observes a sample on the matching histogram label.
#[test]
fn xml_to_proto_success_increments_ok_counter_and_observes_histogram() {
    let xml = br#"<event uid="MIN" type="a-f-G"/>"#;

    let counter = metrics::decode_total();
    let ok_child = counter
        .get_metric_with_label_values(&["xml_to_proto", "ok"])
        .expect("xml_to_proto ok label");
    let ok_before = ok_child.get();

    let hist = metrics::decode_seconds().with_label_values(&["xml_to_proto"]);
    let count_before = hist.get_sample_count();

    xml_to_proto(xml).expect("xml_to_proto must succeed for valid CoT");

    assert_eq!(
        ok_child.get(),
        ok_before + 1,
        "xml_to_proto ok counter must increment by exactly one",
    );
    assert!(
        hist.get_sample_count() > count_before,
        "xml_to_proto histogram must observe at least one sample",
    );
}

/// `proto_to_xml` failure increments the `proto_to_xml, err` counter
/// without polluting the `xml_to_proto` axis — pin the cross-axis
/// label isolation.
#[test]
fn proto_to_xml_failure_does_not_pollute_xml_to_proto_axis() {
    let counter = metrics::decode_total();
    let p2x_err = counter
        .get_metric_with_label_values(&["proto_to_xml", "err"])
        .expect("p2x err label");
    let x2p_ok = counter
        .get_metric_with_label_values(&["xml_to_proto", "ok"])
        .expect("x2p ok label");
    let p2x_err_before = p2x_err.get();
    let x2p_ok_before = x2p_ok.get();

    // Empty buffer is a structurally invalid TakMessage — `proto_to_xml`
    // surfaces a `ProtoError::MissingField` for the absent `cot_event`.
    assert!(proto_to_xml(b"").is_err());

    assert_eq!(
        p2x_err.get(),
        p2x_err_before + 1,
        "proto_to_xml err counter must move",
    );
    assert_eq!(
        x2p_ok.get(),
        x2p_ok_before,
        "xml_to_proto ok counter MUST NOT move on a proto_to_xml failure",
    );
}
