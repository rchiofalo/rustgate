// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]

//! Integration tests for the per-recipient delivery audit hooks
//! introduced by issue #854.
//!
//! The tests pin the externally observable contract of the
//! `OnMessageDelivered` and `OnMessageDropped` callbacks installed via
//! [`Router::set_on_message_delivered`] /
//! [`Router::set_on_message_dropped`]:
//!
//! 1. When a callback is installed, every successful per-recipient
//!    `try_send` fires it once with the documented field set.
//! 2. When no callback is installed (the default), the routing hot
//!    path is silent — the un-installed cost is a single
//!    `ArcSwap::load` + `is_none` check.
//! 3. A saturated channel produces a drop callback with
//!    `reason = "backpressure"`.
//! 4. Multicast / broadcast fan-out fires the callback once per
//!    recipient, with each recipient's CN preserved verbatim.
//! 5. CN fields with embedded CR/LF survive the audit emission as
//!    sanitized records — the in-process callback receives the raw
//!    string per #1207, but the audit-target tracing layer captures
//!    the sanitized form (per the `rustgate_core::audit` boundary).

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

/// Capture of every invocation of the delivered callback for
/// per-test inspection.
#[derive(Clone, Default)]
struct DeliveredRecorder(Arc<Mutex<Vec<DeliveredRecord>>>);

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeliveredRecord {
    source_cn: String,
    dest_cn: String,
    msg_uid: String,
    msg_type: String,
    group: String,
    entity_kind: Option<String>,
    /// PR-C of #852: 32-char lowercase hex render of the W3C `trace_id`
    /// when the routed message carried a trace context inbound; `None`
    /// otherwise.
    trace_id: Option<String>,
}

impl DeliveredRecorder {
    fn snapshot(&self) -> Vec<DeliveredRecord> {
        self.0.lock().unwrap().clone()
    }

    fn callback(&self) -> rustgate_transport::OnMessageDelivered {
        let inner = Arc::clone(&self.0);
        Arc::new(
            move |source_cn, dest_cn, msg_uid, msg_type, group, entity_kind, trace_id| {
                inner.lock().unwrap().push(DeliveredRecord {
                    source_cn: source_cn.to_string(),
                    dest_cn: dest_cn.to_string(),
                    msg_uid: msg_uid.to_string(),
                    msg_type: msg_type.to_string(),
                    group: group.to_string(),
                    entity_kind: entity_kind.map(str::to_owned),
                    trace_id: trace_id.map(str::to_owned),
                });
            },
        )
    }
}

#[derive(Clone, Default)]
struct DroppedRecorder(Arc<Mutex<Vec<DroppedRecord>>>);

#[derive(Clone, Debug, PartialEq, Eq)]
struct DroppedRecord {
    source_cn: String,
    dest_cn: String,
    msg_uid: String,
    reason: String,
}

impl DroppedRecorder {
    fn snapshot(&self) -> Vec<DroppedRecord> {
        self.0.lock().unwrap().clone()
    }

    fn callback(&self) -> rustgate_transport::OnMessageDropped {
        let inner = Arc::clone(&self.0);
        Arc::new(move |source_cn, dest_cn, msg_uid, reason| {
            inner.lock().unwrap().push(DroppedRecord {
                source_cn: source_cn.to_string(),
                dest_cn: dest_cn.to_string(),
                msg_uid: msg_uid.to_string(),
                reason: reason.to_string(),
            });
        })
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

fn make_msg(
    source: &Arc<Identity>,
    dest: Destination,
    payload: &'static [u8],
    msg_type: MessageType,
) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), msg_type),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn message_delivered_audit_fires_when_callback_set() {
    let recorder = DeliveredRecorder::default();
    let router = Router::new();
    router.set_on_message_delivered(Some(recorder.callback()));

    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    let (ptx_a, _prx_a) = mpsc::channel(16);
    let (ntx_a, mut nrx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    let payload: &'static [u8] =
        br#"<event uid="DELIVERY-1" time="2024-01-01T00:00:00Z" type="b-t-f"/>"#;
    router
        .route(make_msg(
            &bob,
            Destination::Direct((*alice).clone()),
            payload,
            MessageType::Chat,
        ))
        .await;

    // Drain the recipient channel so the test does not race the
    // delivery into a dropped envelope.
    let _ = nrx_a.recv().await;

    let records = recorder.snapshot();
    assert_eq!(
        records.len(),
        1,
        "expected exactly one delivered record, got {records:?}"
    );
    assert_eq!(records[0].source_cn, "bob");
    assert_eq!(records[0].dest_cn, "alice");
    assert_eq!(records[0].msg_uid, "DELIVERY-1");
    assert_eq!(records[0].msg_type, "chat");
    assert_eq!(records[0].group, "direct");
}

#[tokio::test(flavor = "current_thread")]
async fn message_delivered_audit_does_not_fire_when_callback_unset() {
    // Default path: the recorder side-channel must remain empty when
    // the operator has not opted into `--audit-delivery`. We assert
    // this by installing a recorder *and immediately replacing it
    // with None* — the router must observe the swap to None and
    // suppress emission.
    let recorder = DeliveredRecorder::default();
    let dropped = DroppedRecorder::default();
    let router = Router::new();
    // Install then revoke to model the runtime swap path.
    router.set_on_message_delivered(Some(recorder.callback()));
    router.set_on_message_dropped(Some(dropped.callback()));
    router.set_on_message_delivered(None);
    router.set_on_message_dropped(None);

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
            br#"<event uid="X" type="a-f-G"/>"#,
            MessageType::Chat,
        ))
        .await;

    let _ = nrx_a.recv().await;

    assert!(
        recorder.snapshot().is_empty(),
        "delivered callback must not fire when the slot has been revoked"
    );
    assert!(
        dropped.snapshot().is_empty(),
        "dropped callback must not fire on the success path"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn message_dropped_audit_fires_on_send_failure() {
    let dropped = DroppedRecorder::default();
    let router = Router::new();
    router.set_on_message_dropped(Some(dropped.callback()));

    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    // Saturate the recipient channels with a length-1 buffer so the
    // first message takes the slot and the second hits backpressure.
    // The second message uses the priority lane (Position) to land on
    // a single-message channel after the first occupies the lane.
    let (ptx_a, _prx_a) = mpsc::channel(1);
    let (ntx_a, _nrx_a) = mpsc::channel(1);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    // Hold a parked receiver for the priority channel by never reading
    // — we'll route Position messages so they go through the priority
    // lane, then route a second to provoke the drop.
    let pos_a: &'static [u8] = br#"<event uid="POS-1" type="a-f-G"/>"#;
    router
        .route(make_msg(
            &bob,
            Destination::Direct((*alice).clone()),
            pos_a,
            MessageType::Position,
        ))
        .await;
    let pos_b: &'static [u8] = br#"<event uid="POS-2" type="a-f-G"/>"#;
    router
        .route(make_msg(
            &bob,
            Destination::Direct((*alice).clone()),
            pos_b,
            MessageType::Position,
        ))
        .await;

    let records = dropped.snapshot();
    assert!(
        !records.is_empty(),
        "expected at least one drop record on saturated channel"
    );
    let backpressure: Vec<&DroppedRecord> = records
        .iter()
        .filter(|r| r.reason == "backpressure")
        .collect();
    assert!(
        !backpressure.is_empty(),
        "expected at least one backpressure record, got {records:?}"
    );
    let first = backpressure[0];
    assert_eq!(first.source_cn, "bob");
    assert_eq!(first.dest_cn, "alice");
    // The dropped record must carry the uid scraped from the original
    // payload — a forensic record must point at the lost message.
    assert!(
        first.msg_uid == "POS-2" || first.msg_uid == "POS-1",
        "dropped record should carry a CoT uid, got {first:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_callbacks_propagate_per_recipient_for_multicast() {
    let recorder = DeliveredRecorder::default();
    let router = Router::new();
    router.set_on_message_delivered(Some(recorder.callback()));

    let sender = make_identity("sender", &["team-a", "team-b"]);
    // Five recipients spread across two groups so the multicast
    // fan-out walks both branches; sender excluded by membership.
    let recipients: Vec<Arc<Identity>> = (0..5)
        .map(|i| {
            let groups: &[&str] = if i % 2 == 0 { &["team-a"] } else { &["team-b"] };
            make_identity(&format!("recip{i}"), groups)
        })
        .collect();

    let mut rxs = Vec::new();
    for r in &recipients {
        let (ptx, _prx) = mpsc::channel(16);
        let (ntx, nrx) = mpsc::channel(16);
        router
            .register(SessionHandle::new(r.clone(), ptx, ntx))
            .await;
        rxs.push(nrx);
    }

    let payload: &'static [u8] =
        br#"<event uid="MCAST-1" time="2024-01-01T00:00:00Z" type="b-t-f"/>"#;
    router
        .route(make_msg(
            &sender,
            Destination::Multicast(vec![Arc::from("team-a"), Arc::from("team-b")]),
            payload,
            MessageType::Chat,
        ))
        .await;

    // Drain so the channel buffers do not exert back-pressure on the
    // delivery loop and skew the count.
    for mut rx in rxs {
        let _ = rx.recv().await;
    }

    let records = recorder.snapshot();
    assert_eq!(
        records.len(),
        5,
        "expected one delivered record per recipient, got {records:?}"
    );
    let unique_dests: BTreeSet<_> = records.iter().map(|r| r.dest_cn.clone()).collect();
    assert_eq!(
        unique_dests.len(),
        5,
        "each multicast recipient must produce a distinct dest_cn record, got {records:?}"
    );
    for r in &records {
        assert_eq!(r.source_cn, "sender");
        assert_eq!(r.msg_uid, "MCAST-1");
        // Multicast preserves the group label per recipient — pin
        // that the group field is one of the addressed groups, not
        // the synthetic "direct" / "broadcast" tag.
        assert!(
            r.group == "team-a" || r.group == "team-b",
            "expected multicast group label, got {r:?}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn audit_event_fields_are_sanitized() {
    // Per the workspace audit-boundary discipline (#1197 / #1220), a
    // CN with embedded CR/LF must NOT survive into the
    // audit-target JSON output as a raw newline. The
    // `rustgate_core::audit::message_delivered` helper invokes
    // `sanitize_for_log` at the boundary; this test pins that the
    // server-side wiring (the standard install in `main.rs`) emits
    // the sanitized form.
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Emit directly through the audit helper — exercising the
    // sanitization boundary without standing up a full router.
    let malicious_cn = "evil\nattacker_line";
    rustgate_core::audit::message_delivered(
        "alice",
        malicious_cn,
        "ATTACK-1",
        "chat",
        "direct",
        None,
        None,
    );

    let captured = buf.snapshot();
    let line = captured
        .lines()
        .find(|l| l.contains("message.delivered"))
        .expect("expected at least one message.delivered audit line");
    let event: serde_json::Value =
        serde_json::from_str(line).expect("audit line must parse as JSON");
    let dest = event["fields"]["dest"]
        .as_str()
        .expect("dest field must be a JSON string");
    assert!(
        !dest.contains('\n'),
        "raw newline must not survive the audit boundary: {dest:?}"
    );
    assert!(
        dest.contains('\u{FFFD}'),
        "sanitized output must contain the U+FFFD replacement codepoint: {dest:?}"
    );

    // Also pin the action / result static tokens so a SIEM rule
    // keying on them keeps firing across refactors.
    assert_eq!(
        event["fields"]["action"]
            .as_str()
            .expect("action must be a JSON string"),
        "deliver"
    );
    assert_eq!(
        event["fields"]["result"]
            .as_str()
            .expect("result must be a JSON string"),
        "success"
    );
}

// ── PR-C of #852: trace_id surfaces in delivery audit ─────────────

/// Build a `RoutableMessage` whose `Metadata.trace_context` carries
/// the canonical W3C example so the delivery audit can be asserted
/// against the well-known 32-char hex `trace_id`.
fn make_msg_with_trace(
    source: &Arc<Identity>,
    dest: Destination,
    payload: &'static [u8],
    msg_type: MessageType,
) -> RoutableMessage {
    let ctx = rustgate_core::TraceContext::new(
        [
            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
            0x47, 0x36,
        ],
        [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7],
        0x01,
    )
    .expect("valid context");
    RoutableMessage {
        source: (**source).clone(),
        destination: dest,
        payload: Bytes::from_static(payload),
        metadata: Metadata::new(SystemTime::now(), "tcp".to_string(), msg_type)
            .with_trace_context(ctx),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn delivery_audit_includes_trace_id_when_metadata_carries_trace_context() {
    // Closes #852 (PR-C). When a routed message carries a W3C trace
    // context on `Metadata.trace_context`, the per-recipient delivery
    // callback receives the 32-char lowercase hex `trace_id` as
    // `Some(&str)`. Pin the SIEM-correlation contract end-to-end so a
    // future refactor that forgot to plumb the field through
    // `emit_message_delivered` is caught at the test boundary.
    let recorder = DeliveredRecorder::default();
    let router = Router::new();
    router.set_on_message_delivered(Some(recorder.callback()));

    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    let (ptx_a, _prx_a) = mpsc::channel(16);
    let (ntx_a, mut nrx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    let payload: &'static [u8] =
        br#"<event uid="TRACE-1" time="2024-01-01T00:00:00Z" type="b-t-f"/>"#;
    router
        .route(make_msg_with_trace(
            &bob,
            Destination::Direct((*alice).clone()),
            payload,
            MessageType::Chat,
        ))
        .await;
    let _ = nrx_a.recv().await;

    let records = recorder.snapshot();
    assert_eq!(
        records.len(),
        1,
        "expected exactly one delivered record, got {records:?}"
    );
    assert_eq!(
        records[0].trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736"),
        "delivery audit must surface trace_id when Metadata.trace_context is Some"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn delivery_audit_omits_trace_id_when_metadata_has_no_trace_context() {
    // Closes #852 (PR-C). The default-path message (no trace context)
    // surfaces `trace_id = None` so the audit record's `trace_id`
    // field stays empty for messages that did not arrive with a W3C
    // `traceparent`. Pin the absence-tolerant default so the SIEM
    // rule that filters on `trace_id != null` does not silently
    // mistreat un-traced traffic.
    let recorder = DeliveredRecorder::default();
    let router = Router::new();
    router.set_on_message_delivered(Some(recorder.callback()));

    let alice = make_identity("alice", &["team"]);
    let bob = make_identity("bob", &["team"]);

    let (ptx_a, _prx_a) = mpsc::channel(16);
    let (ntx_a, mut nrx_a) = mpsc::channel(16);
    router
        .register(SessionHandle::new(alice.clone(), ptx_a, ntx_a))
        .await;

    let payload: &'static [u8] =
        br#"<event uid="NO-TRACE-1" time="2024-01-01T00:00:00Z" type="b-t-f"/>"#;
    router
        .route(make_msg(
            &bob,
            Destination::Direct((*alice).clone()),
            payload,
            MessageType::Chat,
        ))
        .await;
    let _ = nrx_a.recv().await;

    let records = recorder.snapshot();
    assert_eq!(
        records.len(),
        1,
        "expected exactly one delivered record, got {records:?}"
    );
    assert!(
        records[0].trace_id.is_none(),
        "delivery audit must surface trace_id = None when Metadata.trace_context is None, got {:?}",
        records[0].trace_id
    );
}
