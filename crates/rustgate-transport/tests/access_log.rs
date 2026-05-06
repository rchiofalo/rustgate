// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Verifies the per-message access log emitted by `Router::route`:
//!
//! - When a tracing subscriber is attached that admits the
//!   `target = "access"` events, every routed message produces exactly
//!   one JSON line containing the documented fields.
//! - When no subscriber admits the access target (the default),
//!   `Router::route` emits zero access events — the cost is bounded by
//!   a single `tracing::enabled!` check.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_transport::{ACCESS_LOG_TARGET, Router, SessionHandle};
use tokio::sync::mpsc;
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

#[tokio::test(flavor = "current_thread")]
async fn access_log_emits_json_line_per_routed_message() {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target(ACCESS_LOG_TARGET, tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);

    let router = Router::new();
    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    let (ptx_a, prx_a) = mpsc::channel(16);
    let (ntx_a, mut nrx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    let _ = prx_a;

    let payload: &'static [u8] =
        br#"<event uid="ACCESS-1" time="2024-01-01T00:00:00Z" type="a-f-G"/>"#;
    router
        .route(make_msg(
            &bob,
            Destination::Direct((*alice).clone()),
            payload,
        ))
        .await;

    let _ = nrx_a.recv().await;

    let captured = buf.snapshot();

    assert!(
        captured.contains("\"src_cn\":\"bob\""),
        "expected src_cn field, got: {captured}"
    );
    // Direct destinations must hash the CN to a stable opaque token so the
    // access log does not leak raw client identities.
    assert!(
        !captured.contains("\"dst\":\"direct:alice\""),
        "raw CN must not appear in access log dst field, got: {captured}"
    );
    assert!(
        captured.contains("\"dst\":\"direct:"),
        "expected hashed direct dst field, got: {captured}"
    );
    assert!(
        captured.contains("\"msg_uid\":\"ACCESS-1\""),
        "expected msg_uid field, got: {captured}"
    );
    assert!(
        captured.contains("\"outcome\":\"delivered\""),
        "expected delivered outcome, got: {captured}"
    );
    assert!(
        captured.contains("\"size\":"),
        "expected size field, got: {captured}"
    );
    let lines = captured.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(lines, 1, "expected exactly one access line, got {lines}");
}

#[tokio::test(flavor = "current_thread")]
async fn access_log_disabled_by_default_emits_nothing() {
    // Subscriber that admits everything EXCEPT the access target. This
    // mirrors the production default where --access-log is not set.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("rustgate_transport", tracing::Level::TRACE));
    let subscriber = tracing_subscriber::registry().with(layer);

    let _guard = tracing::subscriber::set_default(subscriber);

    let router = Router::new();
    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    let (ptx_a, prx_a) = mpsc::channel(16);
    let (ntx_a, mut nrx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;
    let _ = prx_a;

    router
        .route(make_msg(
            &bob,
            Destination::Direct((*alice).clone()),
            br#"<event uid="X"/>"#,
        ))
        .await;
    let _ = nrx_a.recv().await;

    let captured = buf.snapshot();

    assert!(
        !captured.contains("\"target\":\"access\""),
        "no access events should be emitted when access target is filtered out, got: {captured}"
    );
}
