// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
#![allow(unused_results)]
//! Negative integration test: malformed CoT XML survives store-forward
//! drain without panicking the consumer.
//!
//! Refs #789 / F-134. The store-forward queue stores `RoutableMessage`
//! payloads opaquely as `Bytes`; it does not parse CoT XML on enqueue
//! or drain. The drain side trusts the bytes round-tripped through its
//! own integrity envelope (HMAC + length-prefixed encode) but makes no
//! claim about the *application semantics* of the payload.
//!
//! Practically, this means a downstream consumer that attempts to parse
//! a drained payload as CoT XML can encounter a malformed event — and
//! must handle it cleanly rather than panicking the drain loop. This
//! test pins three properties:
//!
//! 1. **Enqueue tolerates malformed CoT.** The queue accepts a
//!    `RoutableMessage` whose payload is invalid XML; the integrity
//!    envelope works on raw bytes and does not invoke an XML parser.
//! 2. **Drain returns the malformed payload verbatim.** No
//!    silent dropping, no rewriting — the bytes come back exactly as
//!    enqueued, so the consumer is responsible for parsing them.
//! 3. **CoT parsing fails gracefully on the drained payload.** The
//!    `rustgate_cot::parse` function returns a typed `ParseError`
//!    instead of panicking; the drain consumer can log + skip.
//!
//! Together these pin "the queue drains malformed CoT cleanly and the
//! parser refuses it cleanly" — the absence of either property would
//! be a real defect: a panic in the drain loop, or a silent drop that
//! masked a malformed-payload signal a SIEM should see.

use std::collections::BTreeSet;
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::ClientQueue;
use tempfile::TempDir;

/// Three deliberately-malformed CoT XML payloads exercising the parser's
/// error paths. The drain loop must round-trip every variant without
/// panicking, and the parser must reject each one with a typed
/// `ParseError`.
fn malformed_payloads() -> Vec<(&'static str, &'static [u8])> {
    vec![
        // Truncated <event>: closing bracket present, but the document
        // ends before any inner content. quick_xml surfaces this as an
        // `Eof` parse error.
        ("truncated_event", b"<event uid=\"X\""),
        // Mismatched tags — opens <event>, closes </point>. quick_xml
        // returns a "mismatched end tag" error from this shape.
        (
            "mismatched_tags",
            b"<event uid=\"X\" type=\"a-f-G\"></point>",
        ),
        // Schema-invalid: a CoT event missing the mandatory `uid`
        // attribute. The workspace's own `rustgate_cot::parse` enforces
        // the schema and returns `ParseError::MissingAttribute("uid")`.
        (
            "missing_required_uid",
            b"<event type=\"a-f-G\"><point lat=\"0\" lon=\"0\" hae=\"0\"/></event>",
        ),
    ]
}

/// Build a `RoutableMessage` with the given payload bytes. The
/// `source_protocol = "tcp"` matches the path a real session would
/// take through the queue.
fn msg_with_payload(from: &str, to: &str, payload: &'static [u8]) -> RoutableMessage {
    let mut groups = BTreeSet::new();
    groups.insert("alpha".to_string());
    let source = Identity::new(from.to_string(), format!("{from}-fp"), groups).unwrap();
    let dest_groups = BTreeSet::new();
    let dest_id = Identity::new(to.to_string(), format!("{to}-fp"), dest_groups).unwrap();
    RoutableMessage {
        source,
        destination: Destination::Direct(dest_id),
        payload: Bytes::from_static(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Position),
        entity: None,
    }
}

/// Wait until the writer task has materialised `expected` rows in the
/// queue's persistent index. Mirrors the helper used in the unit-level
/// store-forward tests.
async fn wait_for_depth(q: &ClientQueue, cn: &str, expected: u64) {
    for _ in 0..200 {
        if q.stats(cn).depth == expected {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!(
        "timed out waiting for depth={} on {cn} (got {})",
        expected,
        q.stats(cn).depth
    );
}

#[tokio::test]
async fn drain_returns_malformed_cot_payloads_without_panic() {
    let tmp = TempDir::new().unwrap();
    let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();

    // Mix one valid CoT XML message in among the malformed ones, so the
    // test can also assert that the queue does not lose the good
    // messages on drain. The drain order is FIFO; we intentionally
    // alternate to detect any "skip the rest of the batch on first
    // bad payload" regression.
    let valid_cot: &'static [u8] = br#"<event version="2.0" uid="GOOD-1" type="a-f-G" how="m-g" time="2026-01-01T00:00:00.000Z" start="2026-01-01T00:00:00.000Z" stale="2026-01-01T00:05:00.000Z"><point lat="37.0" lon="-122.0" hae="100.0" ce="10.0" le="5.0"/></event>"#;

    let payloads = malformed_payloads();

    // Enqueue 1 good + N malformed in alternating order. Total = N + 1.
    let mut expected_total: u64 = 0;
    q.enqueue("bob", &msg_with_payload("alice", "bob", valid_cot))
        .unwrap();
    expected_total += 1;
    for (_label, bad) in &payloads {
        q.enqueue("bob", &msg_with_payload("alice", "bob", bad))
            .unwrap();
        expected_total += 1;
    }
    wait_for_depth(&q, "bob", expected_total).await;

    // The drain returns every message — store-forward stores payloads
    // opaquely and does not refuse malformed CoT on the queue side.
    let drained = q.drain("bob").unwrap();
    assert_eq!(
        drained.len() as u64,
        expected_total,
        "drain dropped messages: drained={} expected={}",
        drained.len(),
        expected_total,
    );

    // Property (2): the malformed payloads survive verbatim. We don't
    // care about FIFO ordering here — the property is "every enqueued
    // payload is in the drained set".
    let drained_payloads: Vec<&[u8]> = drained.iter().map(|m| m.payload.as_ref()).collect();
    assert!(
        drained_payloads.contains(&valid_cot),
        "valid CoT was lost during drain"
    );
    for (label, bad) in &payloads {
        assert!(
            drained_payloads.contains(bad),
            "malformed payload `{label}` was dropped during drain"
        );
    }

    // Property (3): the CoT parser refuses every malformed payload
    // with a typed error (no panic, no silent acceptance).
    for (label, bad) in &payloads {
        let result = rustgate_cot::parse(bad);
        assert!(
            result.is_err(),
            "expected `{label}` to fail CoT parsing, got Ok({:?})",
            result.ok()
        );
    }

    // Sanity check: the valid event still parses successfully — proves
    // the parser isn't broken for everyone, only refusing the bad
    // payloads.
    let parsed = rustgate_cot::parse(valid_cot).expect("valid CoT must parse");
    assert_eq!(parsed.uid, "GOOD-1");
    assert_eq!(parsed.event_type, "a-f-G");

    // Drain bookkeeping: one drain call observed.
    assert_eq!(q.drains_total(), 1);
    // No tampered or expired entries — the malformed-PAYLOAD path is
    // distinct from the malformed-ENVELOPE path the existing tests
    // pin (see `reopen_purges_malformed_entries` and
    // `store_forward_hmac_rejects_tampered`).
    assert_eq!(q.tampered_total(), 0);
    assert_eq!(q.expired_total(), 0);
}
