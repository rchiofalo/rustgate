// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Captures `target="audit"` events for the SIEM forwarder.
//!
//! The layer runs inside every `tracing` call that emits an audit event,
//! so it does as little as possible: copy the fields into an owned
//! [`AuditRecord`] and `try_send` it to a bounded queue. Formatting and
//! network I/O happen on the forwarder task. A full queue drops the record
//! and counts it rather than ever blocking the caller.
//!
//! The layer must never emit `tracing` events itself: an audit event
//! emitted here would re-enter this layer.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// The `tracing` target every audit event uses (`rustgate_core::audit`).
pub(crate) const AUDIT_TARGET: &str = "audit";

/// Event type given to an audit-target event that carries no
/// `event_type` field (e.g. a plain `warn!(target: "audit", ...)`), so it
/// is still forwarded rather than silently dropped.
pub(crate) const UNTYPED_EVENT: &str = "audit.untyped";

/// Audit events withheld from the SIEM unless `--siem-include-classified`
/// is set. `authz.classified_delivery` records the plaintext CNs of
/// classified-artefact recipients by design; sending it to a SIEM cleared
/// below the traffic's classification is a cross-domain leak (see the
/// handling caveat on `rustgate_core::audit::authz_classified_delivery`).
pub(crate) const CLASSIFIED_EVENTS: &[&str] = &["authz.classified_delivery"];

/// One audit event, copied out of `tracing` for the forwarder task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditRecord {
    /// When the layer saw the event.
    pub(crate) at: OffsetDateTime,
    /// The dot-notation event type, e.g. `client.rejected`.
    pub(crate) event_type: String,
    /// Every other field, in emission order, rendered as text.
    pub(crate) fields: Vec<(String, String)>,
}

impl AuditRecord {
    /// The value of field `name`, if present.
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Counters shared between the layer and the forwarder.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    /// Records dropped because the queue was full.
    pub(crate) dropped_queue_full: AtomicU64,
    /// Records written to the SIEM connection.
    pub(crate) sent: AtomicU64,
    /// Records dropped after a write failed and the retry also failed, or
    /// left in the queue at shutdown.
    pub(crate) dropped_undelivered: AtomicU64,
}

/// `tracing` layer that forwards audit events to the SIEM queue.
pub(crate) struct SiemLayer {
    tx: mpsc::Sender<AuditRecord>,
    include_classified: bool,
    stats: Arc<Stats>,
}

impl SiemLayer {
    pub(crate) fn new(
        tx: mpsc::Sender<AuditRecord>,
        include_classified: bool,
        stats: Arc<Stats>,
    ) -> Self {
        Self {
            tx,
            include_classified,
            stats,
        }
    }
}

impl<S: Subscriber> Layer<S> for SiemLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        let event_type = visitor
            .event_type
            .unwrap_or_else(|| UNTYPED_EVENT.to_owned());
        if !self.include_classified && CLASSIFIED_EVENTS.contains(&event_type.as_str()) {
            return;
        }
        let record = AuditRecord {
            at: OffsetDateTime::now_utc(),
            event_type,
            fields: visitor.fields,
        };
        if self.tx.try_send(record).is_err() {
            let _ = self
                .stats
                .dropped_queue_full
                .fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "metrics")]
            crate::metrics::siem_events_dropped()
                .with_label_values(&["queue_full"])
                .inc();
        }
    }
}

#[derive(Default)]
struct Visitor {
    event_type: Option<String>,
    fields: Vec<(String, String)>,
}

impl Visitor {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "event_type" {
            self.event_type = Some(value);
        } else {
            self.fields.push((field.name().to_owned(), value));
        }
    }
}

impl Visit for Visitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    fn capture(include_classified: bool, capacity: usize, emit: impl FnOnce()) -> Vec<AuditRecord> {
        let (tx, mut rx) = mpsc::channel(capacity);
        let layer = SiemLayer::new(tx, include_classified, Arc::new(Stats::default()));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, emit);
        let mut out = Vec::new();
        while let Ok(record) = rx.try_recv() {
            out.push(record);
        }
        out
    }

    #[test]
    fn captures_audit_events_with_their_fields_in_order() {
        let peer: std::net::SocketAddr = "203.0.113.7:44100".parse().unwrap();
        let records = capture(false, 8, || {
            rustgate_core::audit::connection_rejected(peer, "connection limit reached");
        });
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.event_type, "client.rejected");
        assert_eq!(record.field("peer"), Some("203.0.113.7:44100"));
        assert_eq!(record.field("reason"), Some("connection limit reached"));
        assert_eq!(record.field("result"), Some("rejected"));
    }

    #[test]
    fn forwards_audit_events_without_an_event_type() {
        let records = capture(false, 8, || {
            tracing::warn!(target: "audit", flip = "no-policy-deny", "insecure default in use");
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, UNTYPED_EVENT);
        assert_eq!(records[0].field("flip"), Some("no-policy-deny"));
        assert_eq!(records[0].field("message"), Some("insecure default in use"));
    }

    #[test]
    fn ignores_events_on_other_targets() {
        let records = capture(false, 8, || {
            tracing::info!(event_type = "client.rejected", "not an audit event");
            tracing::info!(target: "access", event_type = "x.y", "access log");
        });
        assert!(records.is_empty());
    }

    #[test]
    fn withholds_classified_delivery_unless_opted_in() {
        let emit = || {
            rustgate_core::audit::authz_classified_delivery(
                "alice",
                "bob",
                "receive",
                "group",
                "blue",
                Some("rule-1"),
                "policy-1",
            );
        };
        assert!(capture(false, 8, emit).is_empty());
        let records = capture(true, 8, emit);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, "authz.classified_delivery");
    }

    #[test]
    fn a_full_queue_drops_and_counts_instead_of_blocking() {
        let (tx, mut rx) = mpsc::channel(2);
        let stats = Arc::new(Stats::default());
        let layer = SiemLayer::new(tx, false, Arc::clone(&stats));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..5 {
                rustgate_core::audit::server_started("127.0.0.1:8089", "test");
            }
        });
        let mut delivered = 0;
        while rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 2);
        assert_eq!(stats.dropped_queue_full.load(Ordering::Relaxed), 3);
    }
}
