// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Integration test for the store-forward dwell-time audit signal.
//!
//! Issue #729 — when a client reconnects and the store-forward queue is
//! drained on its behalf, an `audit::store_forward_drained` event is
//! emitted carrying `count`, `dwell_seconds_mean`, `dwell_seconds_min`,
//! `dwell_seconds_max`, `expired_count`, and `tampered_count`. This
//! test pins the on-the-wire shape of that event so a SIEM
//! correlation tool can rely on the field names being stable.
//!
//! This test lives in `tests/` (integration) rather than alongside the
//! `store_forward` unit tests because tracing caches per-callsite
//! `Interest` globally — under cargo's parallel-test thread pool,
//! once any test in the same binary emits an `audit!` event without
//! a subscriber installed, the default no-op subscriber returns
//! `Interest::never()` for that callsite and the result is cached
//! process-wide, blocking subsequent thread-local subscribers from
//! reaching it. Integration tests run in their own binary, so the
//! callsite cache only collects from this file's emissions.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::ClientQueue;
use tempfile::TempDir;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        let g = self.0.lock().unwrap();
        String::from_utf8_lossy(&g).into_owned()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn ident(cn: &str) -> Identity {
    let mut groups = BTreeSet::new();
    let _ = groups.insert("alpha".to_string());
    Identity::new(cn.to_string(), format!("{cn}-fp"), groups).unwrap()
}

fn msg_for(from: &str, to: &str, payload: &[u8]) -> RoutableMessage {
    RoutableMessage {
        source: ident(from),
        destination: Destination::Direct(ident(to)),
        payload: Bytes::copy_from_slice(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Chat),
        entity: None,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn drain_audit_includes_dwell_seconds() {
    // Capture only the audit target, mirroring production behaviour
    // where audit output is routed to a distinct sink.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let tmp = TempDir::new().unwrap();
    let q = ClientQueue::open(tmp.path(), 1_000_000).unwrap();

    // Admit a message and wait for the writer task to land it in the
    // in-memory index. The drain path also reads from redb, so we
    // additionally poll the database directly to avoid a race window
    // where the in-memory index claims depth=1 but the redb commit
    // has not yet committed.
    q.enqueue("bob", &msg_for("alice", "bob", b"slow")).unwrap();
    for _ in 0..200 {
        if q.stats("bob").depth == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(q.stats("bob").depth, 1, "writer task must land the entry");
    // The in-memory index is updated BEFORE the redb commit lands. A
    // drain immediately after `wait_for_depth` may find the row
    // missing on the persistent side and silently emit no events. A
    // single 50ms sleep is sufficient — the writer task commits in a
    // single redb transaction, no further work pending.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Sleep ~100ms more so dwell is unambiguously above the noise
    // floor (a few ms of channel-send latency).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drain must return the message and emit the audit event.
    let drained = q.drain("bob").unwrap();
    assert_eq!(
        drained.len(),
        1,
        "drain must return the single persisted message"
    );

    let snapshot = buf.snapshot();
    assert!(
        !snapshot.is_empty(),
        "audit subscriber must capture at least the drained event"
    );

    // Find the JSON line that carries our drained event and parse its
    // fields. The fmt layer emits one JSON object per event.
    let line = snapshot
        .lines()
        .find(|l| l.contains("store_forward.drained"))
        .unwrap_or_else(|| {
            panic!(
                "audit log must contain a `store_forward.drained` event; \
                 got: {snapshot}"
            )
        });
    let parsed: serde_json::Value =
        serde_json::from_str(line).expect("audit line must be valid JSON");

    assert_eq!(
        parsed["target"], "audit",
        "event must target the audit sink"
    );
    assert_eq!(parsed["level"], "INFO", "audit events are emitted at INFO");

    let fields = &parsed["fields"];
    assert_eq!(
        fields["event_type"], "store_forward.drained",
        "event_type field must match the audit helper",
    );
    assert_eq!(
        fields["cn"], "bob",
        "cn field must reflect the drained destination",
    );
    assert_eq!(
        fields["count"], 1,
        "count must reflect the single drained message",
    );
    assert_eq!(
        fields["expired_count"], 0,
        "expired_count must be zero for a fresh, non-TTL message",
    );
    assert_eq!(
        fields["tampered_count"], 0,
        "tampered_count must be zero for a non-tampered message",
    );

    let dwell_mean = fields["dwell_seconds_mean"]
        .as_f64()
        .expect("dwell_seconds_mean must be a numeric field");
    let dwell_min = fields["dwell_seconds_min"]
        .as_f64()
        .expect("dwell_seconds_min must be a numeric field");
    let dwell_max = fields["dwell_seconds_max"]
        .as_f64()
        .expect("dwell_seconds_max must be a numeric field");

    // We slept ~150ms after admission. Allow a generous lower bound
    // (50ms) to absorb scheduling jitter under CI load while still
    // catching a "dwell == 0" regression.
    assert!(
        dwell_mean >= 0.05,
        "dwell_seconds_mean ({dwell_mean}) must reflect the ~150ms wait"
    );
    assert!(
        dwell_min >= 0.05,
        "dwell_seconds_min ({dwell_min}) must reflect the ~150ms wait"
    );
    assert!(
        dwell_max >= 0.05,
        "dwell_seconds_max ({dwell_max}) must reflect the ~150ms wait"
    );

    // Sanity: with one message, mean == min == max.
    assert!(
        (dwell_mean - dwell_min).abs() < 1e-9,
        "single-message drain: mean ({dwell_mean}) must equal min ({dwell_min})"
    );
    assert!(
        (dwell_mean - dwell_max).abs() < 1e-9,
        "single-message drain: mean ({dwell_mean}) must equal max ({dwell_max})"
    );
}
