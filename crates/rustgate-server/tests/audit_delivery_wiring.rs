// Copyright © 2026 Roberto Chiofalo.

#![allow(clippy::panic, clippy::unwrap_used)]
#![allow(unused_results)]
//! Audit-delivery CLI flag wiring test (closes #854).
//!
//! `rustgate-server`'s `main.rs` reads `cli.audit_delivery` and
//! installs the per-recipient delivery / drop callbacks pointing at
//! the `rustgate_core::audit::message_delivered` /
//! `message_dropped` helpers. When the flag is unset (the default),
//! the slots stay `None` so the routing hot path is silent. This
//! test exercises both arms via the `Router::set_on_message_*`
//! public surface and pins the externally observable contract:
//!
//! - With the wiring installed (mirroring the `--audit-delivery` arm
//!   in `main.rs`), the audit helper is invoked and emits a
//!   `message.delivered` event with the documented shape — the same
//!   contract the per-recipient callback chain produces in
//!   production.
//! - With the wiring **not** installed (mirroring the default arm),
//!   no audit event is emitted regardless of how many recipients the
//!   router visits.
//!
//! `rustgate-server` is a binary-only crate, so this test exercises
//! the `rustgate_transport::Router::set_on_message_delivered` /
//! `set_on_message_dropped` boundary directly rather than driving
//! the binary via `std::process::Command`. The CLI parsing contract
//! itself is pinned by `cli_audit_delivery_*` in `cli.rs`.
//!
//! Lives in its own integration-test binary for the same reason
//! `admin_drain_audit.rs` does: tracing caches per-callsite
//! `Interest` globally, so once any in-process test emits an
//! `audit!` event without a subscriber installed, the default no-op
//! subscriber returns `Interest::never()` for that callsite and the
//! result is cached process-wide, blocking subsequent thread-local
//! subscribers from reaching it.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{Router, SessionHandle};
use tokio::sync::mpsc;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
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

fn make_identity(cn: &str, groups: &[&str]) -> Arc<Identity> {
    Arc::new(
        Identity::new(
            cn.to_string(),
            format!("{cn}-fp"),
            groups
                .iter()
                .map(|g| g.to_string())
                .collect::<BTreeSet<_>>(),
        )
        .expect("valid identity"),
    )
}

fn make_msg(source: &Arc<Identity>, dest: Destination, payload: &'static [u8]) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), MessageType::Chat),
    }
}

#[test]
fn audit_delivery_cli_flag_wires_callbacks() {
    // Arrange a tracing subscriber that captures the `audit` target so
    // we can observe the wire shape an opt-in deployment sees.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let captured = tracing::subscriber::with_default(subscriber, || {
        // Drive an async block synchronously inside the subscriber
        // scope so the captured snapshot reflects only this test's
        // emissions.
        runtime.block_on(async {
            let router = Router::new();

            // Mirror the `cli.audit_delivery == true` arm of
            // `main.rs`: install the audit-emitting callbacks.
            router.set_on_message_delivered(Some(Arc::new(
                |source_cn, dest_cn, msg_uid, msg_type, group| {
                    rustgate_core::audit::message_delivered(
                        source_cn, dest_cn, msg_uid, msg_type, group,
                    );
                },
            )));
            router.set_on_message_dropped(Some(Arc::new(|source_cn, dest_cn, msg_uid, reason| {
                rustgate_core::audit::message_dropped(source_cn, dest_cn, msg_uid, reason);
            })));

            let alice = make_identity("alice", &["team"]);
            let bob = make_identity("bob", &["team"]);
            let (ptx_a, _prx_a) = mpsc::channel(16);
            let (ntx_a, mut nrx_a) = mpsc::channel(16);
            router
                .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
                .await;

            router
                .route(make_msg(
                    &bob,
                    Destination::Direct((*alice).clone()),
                    br#"<event uid="WIRED-1" type="b-t-f"/>"#,
                ))
                .await;
            let _ = nrx_a.recv().await;
        });

        buf.snapshot()
    });

    let line = captured
        .lines()
        .find(|l| l.contains("message.delivered"))
        .expect("audit event message.delivered must be emitted when CLI flag is set");
    let event: serde_json::Value =
        serde_json::from_str(line).expect("audit line must parse as JSON");
    assert_eq!(
        event["fields"]["event_type"].as_str(),
        Some("message.delivered"),
    );
    assert_eq!(event["fields"]["source"].as_str(), Some("bob"));
    assert_eq!(event["fields"]["dest"].as_str(), Some("alice"));
    assert_eq!(event["fields"]["uid"].as_str(), Some("WIRED-1"));
    assert_eq!(event["fields"]["msg_type"].as_str(), Some("chat"));
    assert_eq!(event["fields"]["group"].as_str(), Some("direct"));
    assert_eq!(event["fields"]["action"].as_str(), Some("deliver"));
    assert_eq!(event["fields"]["result"].as_str(), Some("success"));
}

#[test]
fn audit_delivery_cli_flag_unset_leaves_callbacks_silent() {
    // Mirror the `cli.audit_delivery == false` arm: the callbacks
    // are NEVER installed (the slots stay `None`), so no audit
    // record is emitted regardless of how many messages the router
    // routes.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let captured = tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let router = Router::new();
            // Deliberately do NOT install any callback.
            let alice = make_identity("alice", &["team"]);
            let bob = make_identity("bob", &["team"]);
            let (ptx_a, _prx_a) = mpsc::channel(16);
            let (ntx_a, mut nrx_a) = mpsc::channel(16);
            router
                .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
                .await;
            router
                .route(make_msg(
                    &bob,
                    Destination::Direct((*alice).clone()),
                    br#"<event uid="QUIET-1" type="b-t-f"/>"#,
                ))
                .await;
            let _ = nrx_a.recv().await;
        });

        buf.snapshot()
    });

    assert!(
        !captured.contains("message.delivered"),
        "audit event must NOT fire when --audit-delivery is unset; got:\n{captured}"
    );
    assert!(
        !captured.contains("message.dropped"),
        "audit event must NOT fire when --audit-delivery is unset; got:\n{captured}"
    );
}
