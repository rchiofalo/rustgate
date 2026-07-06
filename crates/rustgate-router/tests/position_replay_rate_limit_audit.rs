// Copyright © 2026 Roberto Chiofalo.

#![allow(unused_results)]
#![allow(clippy::panic, clippy::unwrap_used)]
//! Audit-trail regression test for the position-replay rate limiter.
//!
//! `Router::replay_positions` is gated by a per-CN [`TokenBucket`]
//! (issue #724). When the bucket is empty the replay is shed and
//! [`rustgate_core::audit::position_replay_rate_limited`] emits a
//! structured event so a SIEM can detect flap-looping clients. This
//! test pins the audit contract: target, fields, and PII-safe rendering
//! must not regress if the helper's signature is ever changed.
//!
//! Lives in its own integration-test binary so the thread-local audit
//! subscriber installed here cannot race subscribers installed by other
//! in-process tests (the failure mode that motivated splitting this
//! out of the lib `mod tests` block).

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};
use rustgate_router::{PositionReplayLimitConfig, Router, SessionHandle};
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

fn make_position(source: &Arc<Identity>) -> RoutableMessage {
    RoutableMessage {
        source: (**source).clone(),
        destination: Destination::Broadcast,
        payload: Bytes::from_static(b"<event/>"),
        metadata: Metadata::new(SystemTime::now(), "cot".to_string(), MessageType::Position),
        entity: None,
    }
}

#[test]
fn replay_positions_emits_audit_on_rate_limit() {
    let buf = SharedBuf::default();
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(buf.clone())
        .with_filter(Targets::new().with_target("audit", tracing::Level::INFO));
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // `current_thread` so the default subscriber stays installed on the
    // emitting thread for the entire async body.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        // burst=1 + rate=0 → exactly one replay allowed, the next call
        // is shed and audited.
        let router = Router::new().with_position_replay_limit(PositionReplayLimitConfig::new(0, 1));
        let alice = make_identity("alice", &["alpha"]);
        let bob = make_identity("bob", &["alpha"]);
        router.cache().store(make_position(&alice));

        let (ptx, prx) = mpsc::channel(16);
        let (ntx, nrx) = mpsc::channel(16);
        let handle = SessionHandle::new(bob.clone(), ptx, ntx);
        router.replay_positions(&handle).await; // consumes the only token
        drop(prx);
        drop(nrx);

        let (ptx2, prx2) = mpsc::channel(16);
        let (ntx2, nrx2) = mpsc::channel(16);
        let handle2 = SessionHandle::new(bob.clone(), ptx2, ntx2);
        router.replay_positions(&handle2).await; // shed → audited
        drop(prx2);
        drop(nrx2);
    });

    let snapshot = buf.snapshot();
    let line = snapshot
        .lines()
        .find(|l| l.contains("position_replay.rate_limited"))
        .unwrap_or_else(|| {
            panic!(
                "position_replay.rate_limited audit event must be emitted, \
                 snapshot was: {snapshot}"
            )
        });
    let parsed: serde_json::Value =
        serde_json::from_str(line).expect("audit line must be valid JSON");

    assert_eq!(
        parsed["target"], "audit",
        "event must target the audit sink for SIEM routing"
    );
    assert_eq!(parsed["level"], "INFO", "audit events are emitted at INFO");

    let fields = &parsed["fields"];
    assert_eq!(
        fields["event_type"], "position_replay.rate_limited",
        "event_type must match the documented audit event name"
    );
    assert_eq!(
        fields["action"], "rate_limit",
        "action field must classify this as a rate-limit event"
    );
    assert_eq!(
        fields["result"], "shed",
        "result must distinguish a shed replay from an admitted partial replay"
    );
    assert_eq!(
        fields["allowed"], 0,
        "the deny path reports zero positions delivered"
    );
    assert!(
        fields["session"].as_str().is_some_and(|s| !s.is_empty()),
        "session field must carry the PII-safe hash_cn rendering of the CN"
    );
    // `attempted` is the count of cached positions that *would* have
    // been considered. The cache holds exactly one position in this
    // test, so the audited count must mirror it.
    assert_eq!(
        fields["attempted"], 1,
        "attempted field must report the cache size at the moment the bucket emptied"
    );
}
