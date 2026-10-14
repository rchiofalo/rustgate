// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! Audit-trail regression test for `POST /api/drain` (closes #791).
//!
//! `drain_handler` in `crates/rustgate-server/src/mgmt_api.rs` emits a
//! `rustgate_core::audit::admin_drain_triggered("api")` event at the
//! moment the shared shutdown `Notify` is fired. SIEM correlation
//! rules key on the `event_type` / `action` / `result` / `source`
//! tuple to distinguish API-initiated drains from SIGTERM-initiated
//! ones — pin the wire shape of the underlying audit helper here so a
//! future refactor that drops the emission, renames a field, or fans
//! the source token out without updating this test fails loudly.
//!
//! Lives in its own integration-test binary so the thread-local audit
//! subscriber installed here cannot race subscribers installed by other
//! in-process tests — tracing caches per-callsite `Interest` globally,
//! so once any test in the same binary emits an `audit!` event without
//! a subscriber installed, the default no-op subscriber returns
//! `Interest::never()` for that callsite and the result is cached
//! process-wide, blocking subsequent thread-local subscribers from
//! reaching it. Same rationale as
//! `rustgate-transport/tests/mask_point_recovery_audit.rs`. The
//! handler-level wiring (route → audit call) is pinned by the
//! `admin_drain_*` unit tests in `mgmt_api.rs` that drive the
//! handler directly without a subscriber.
//!
//! `rustgate-server` is a binary-only crate, so this test exercises
//! the `rustgate_core::audit::admin_drain_triggered` boundary
//! directly rather than going through the HTTP route. The
//! handler-level pin lives in the unit-test module.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buf poisoned")).into_owned()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buf poisoned").extend_from_slice(buf);
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

#[test]
fn admin_drain_triggered_emits_pinned_audit_shape() {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        rustgate_core::audit::admin_drain_triggered("api");
    });

    let snapshot = buf.snapshot();
    let line = snapshot
        .lines()
        .find(|l| l.contains("admin.drain_triggered"))
        .expect("audit event admin.drain_triggered must be emitted");
    let event: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(
        event["fields"]["event_type"].as_str(),
        Some("admin.drain_triggered"),
        "event_type must match the documented SIEM-correlation token",
    );
    assert_eq!(
        event["fields"]["source"].as_str(),
        Some("api"),
        "source must be the literal token the metric label uses",
    );
    assert_eq!(
        event["fields"]["action"].as_str(),
        Some("drain"),
        "action must be the documented audit verb",
    );
    assert_eq!(
        event["fields"]["result"].as_str(),
        Some("initiated"),
        "result must reflect the immediate-return contract",
    );
}
