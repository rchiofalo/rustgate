// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(clippy::panic, clippy::unwrap_used)]
//! Audit-trail regression test for the `/api/v1/*` management endpoints
//! (refs #902).
//!
//! Successful access to `/api/v1/crl` and `/api/v1/dedup/stats` emits a
//! `rustgate_core::audit::mgmt_api_accessed(endpoint, identity)` event
//! at the moment the response payload is computed. SIEM correlation
//! rules key on the `event_type` / `action` / `result` / `endpoint` /
//! `identity` tuple to attribute operator-driven reads — pin the wire
//! shape of the underlying audit helper here so a future refactor that
//! drops the emission, renames a field, or fans the endpoint token out
//! without updating this test fails loudly.
//!
//! Lives in its own integration-test binary so the thread-local audit
//! subscriber installed here cannot race subscribers installed by other
//! in-process tests — tracing caches per-callsite `Interest` globally,
//! so once any test in the same binary emits an `audit!` event without
//! a subscriber installed, the default no-op subscriber returns
//! `Interest::never()` for that callsite and the result is cached
//! process-wide, blocking subsequent thread-local subscribers from
//! reaching it. Same rationale as `admin_drain_audit.rs` and
//! `rustgate-transport/tests/mask_point_recovery_audit.rs`.
//!
//! `rustgate-server` is a binary-only crate, so this test exercises
//! the `rustgate_core::audit::mgmt_api_accessed` boundary directly
//! rather than going through the HTTP route. The handler-level wiring
//! (route → audit call) is pinned by the `mgmt_v1_*` unit tests in
//! `mgmt_api.rs` that drive the handler directly without a subscriber.

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
fn mgmt_api_accessed_emits_pinned_audit_shape() {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        rustgate_core::audit::mgmt_api_accessed("/api/v1/crl", "bearer");
    });

    let snapshot = buf.snapshot();
    let line = snapshot
        .lines()
        .find(|l| l.contains("mgmt.api_accessed"))
        .expect("audit event mgmt.api_accessed must be emitted");
    let event: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(
        event["fields"]["event_type"].as_str(),
        Some("mgmt.api_accessed"),
        "event_type must match the documented SIEM-correlation token",
    );
    assert_eq!(
        event["fields"]["endpoint"].as_str(),
        Some("/api/v1/crl"),
        "endpoint must echo the route the operator hit verbatim",
    );
    assert_eq!(
        event["fields"]["identity"].as_str(),
        Some("bearer"),
        "identity must reflect the authenticated principal",
    );
    assert_eq!(
        event["fields"]["action"].as_str(),
        Some("access"),
        "action must be the documented audit verb",
    );
    assert_eq!(
        event["fields"]["result"].as_str(),
        Some("success"),
        "result must indicate success — failures are 401-and-no-emission",
    );
}

#[test]
fn client_force_disconnected_emits_pinned_audit_shape() {
    // Closes #902 — pin the wire shape of the
    // `client.force_disconnected` audit event. SIEM correlation rules
    // key on the `event_type` / `action` / `result` / `cn` /
    // `by_operator` / numeric `sessions_closed` tuple to attribute
    // operator-driven disconnects, so a future refactor that drops
    // the emission, renames a field, or swaps the numeric/string
    // positions must fail loudly.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        rustgate_core::audit::client_force_disconnected("alice", "bearer", 1);
    });

    let snapshot = buf.snapshot();
    let line = snapshot
        .lines()
        .find(|l| l.contains("client.force_disconnected"))
        .expect("audit event client.force_disconnected must be emitted");
    let event: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(
        event["fields"]["event_type"].as_str(),
        Some("client.force_disconnected"),
        "event_type must match the documented SIEM-correlation token",
    );
    assert_eq!(
        event["fields"]["cn"].as_str(),
        Some("alice"),
        "cn must echo the URL path segment verbatim",
    );
    assert_eq!(
        event["fields"]["by_operator"].as_str(),
        Some("bearer"),
        "by_operator must reflect the authenticated principal",
    );
    assert_eq!(
        event["fields"]["sessions_closed"].as_u64(),
        Some(1),
        "sessions_closed must be a JSON number, not a string",
    );
    assert_eq!(
        event["fields"]["action"].as_str(),
        Some("force_disconnect"),
        "action must be the documented audit verb",
    );
    assert_eq!(
        event["fields"]["result"].as_str(),
        Some("success"),
        "result must indicate success — auth failures are 401-and-no-emission",
    );
}

#[test]
fn mgmt_api_accessed_sanitizes_endpoint_at_audit_boundary() {
    // A pathological caller injecting CR/LF into the `endpoint` field
    // (per #1197 / #1220 hardening) MUST be sanitized at the audit
    // boundary so the emitted log line cannot be log-forged. The
    // sanitizer replaces control characters with U+FFFD, which renders
    // unambiguously in the JSON output. Pin the contract.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        rustgate_core::audit::mgmt_api_accessed("/api/v1/crl\nFAKE EVENT", "bearer");
    });

    let snapshot = buf.snapshot();
    let line = snapshot
        .lines()
        .find(|l| l.contains("mgmt.api_accessed"))
        .expect("audit event must be emitted");
    let event: serde_json::Value = serde_json::from_str(line).unwrap();
    let endpoint = event["fields"]["endpoint"]
        .as_str()
        .expect("endpoint field must be a string");
    assert!(
        !endpoint.contains('\n'),
        "endpoint sanitizer must strip control characters: {endpoint}"
    );
}
