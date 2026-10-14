// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Regression test for the store-forward drain panic audit signal.
//!
//! `Router::drain_offline_messages` runs [`redb`] work inside
//! `tokio::task::spawn_blocking`. Prior to this fix, a panic in the
//! blocking task produced only an ephemeral `warn!` — a SIEM would never
//! see that a client's queued messages were silently lost on reconnect.
//!
//! The fix emits [`rustgate_core::audit::store_forward_drain_panic`] on
//! the join-error branch. This test verifies the audit helper produces
//! the expected structured event (target, name, action, result, fields)
//! when invoked with the error text of a real `JoinError` from a
//! panicking `spawn_blocking` body — so the compliance-trail contract
//! does not regress if the helper's fields are ever renamed.

use std::io::Write;
use std::sync::{Arc, Mutex};

use rustgate_core::audit::store_forward_drain_panic;
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

#[tokio::test(flavor = "current_thread")]
async fn store_forward_drain_panic_emits_audit_event_on_join_error() {
    // Capture only the audit target, mirroring production behavior where
    // audit output is routed to a distinct sink.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Force a real `JoinError` by panicking inside `spawn_blocking` — the
    // exact failure mode the router guards against.
    let join_err = tokio::task::spawn_blocking(|| {
        panic!("simulated redb panic");
    })
    .await
    .expect_err("panicking spawn_blocking must produce a JoinError");
    assert!(
        join_err.is_panic(),
        "JoinError must classify as panic for the audit contract to be meaningful"
    );

    store_forward_drain_panic("deadbeef1234cafe", &join_err.to_string());

    let snapshot = buf.snapshot();
    assert!(
        !snapshot.is_empty(),
        "audit event must be captured by target=audit subscriber"
    );

    // Parse each JSON line and assert the documented field shape. The
    // structured-fmt layer writes one JSON object per event.
    let line = snapshot
        .lines()
        .find(|l| l.contains("store_forward.drain_panic"))
        .expect("audit event store_forward.drain_panic must be emitted");
    let parsed: serde_json::Value = serde_json::from_str(line).expect("audit line must be JSON");

    assert_eq!(
        parsed["target"], "audit",
        "event must target the audit sink"
    );
    assert_eq!(parsed["level"], "INFO", "audit events are emitted at INFO");
    let fields = &parsed["fields"];
    assert_eq!(
        fields["event_type"], "store_forward.drain_panic",
        "event_type must match the audit event name for SIEM routing"
    );
    assert_eq!(
        fields["session"], "deadbeef1234cafe",
        "session field must pass through the PII-safe hash unchanged"
    );
    assert_eq!(
        fields["action"], "drain_queue",
        "action must mark this as a drain_queue event for SIEM routing"
    );
    assert_eq!(
        fields["result"], "panic",
        "result must distinguish panic from successful drain or storage error"
    );
    assert!(
        fields["error"]
            .as_str()
            .is_some_and(|e| e.contains("panic")),
        "error field must carry the JoinError rendering so operators see the cause"
    );
}
