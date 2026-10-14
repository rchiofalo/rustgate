// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-target in-memory batcher for HTTP egress.
//!
//! Accumulates already-serialized single-message bodies and yields a
//! flush payload when either the count threshold or the byte threshold
//! is reached. The batcher is *synchronous* and *bounded* — the actual
//! HTTP request and retry loop happen outside this module, on the
//! per-target dispatch path in [`crate::publisher`].
//!
//! The batcher has no notion of time. A time-based flush (so a trickle
//! of low-volume traffic doesn't sit idle under the count threshold) is
//! a deliberate follow-up — this module only owns the count/bytes
//! trigger so the initial batch PR stays small and the time-based
//! scheduler can be added against a stable state machine.
//!
//! # Concurrency
//!
//! Each `Batcher` is single-owner; the per-target mutex lives one level
//! up in `TargetState`. Callers must hold the mutex across `push` /
//! `drain`.

use std::sync::Arc;

use bytes::Bytes;
use rustgate_resilience::backpressure::BackpressurePermit;

/// A single-message entry buffered in a [`Batcher`].
///
/// Holds the serialized body that will be concatenated at flush time by
/// [`crate::payload::render_batch`], plus the originating message's
/// backpressure permit so the gate keeps accounting for the buffered
/// bytes until they are actually flushed and sent (a future DLQ-on-
/// terminal-batch-failure follow-up will grow this to also carry an
/// `Arc<RoutableMessage>` for per-message dead-lettering).
#[derive(Debug, Clone)]
pub(crate) struct BatchEntry {
    /// Serialized single-message body produced by
    /// [`crate::payload::serialize`] before the batch decision.
    pub(crate) body: Bytes,
    /// Backpressure reservation for this buffered body. Held for the
    /// lifetime of the entry so the gate's in-flight byte accounting
    /// stays accurate while the body sits in the batcher; released when
    /// the flush payload that owns this entry is dropped after the send.
    /// `None` when the gate is disabled.
    // justification: pure RAII — kept only so its `Drop` releases the
    // gate reservation once the entry is flushed; never read directly.
    #[allow(dead_code)]
    pub(crate) permit: Option<Arc<BackpressurePermit>>,
}

/// Why the batcher emitted a flush payload.
///
/// Threaded into the `rustgate_http_batches_flushed_total{target,reason}`
/// Prometheus counter by the publisher so operators can distinguish
/// "tuned correctly" (count or bytes) from "drain at shutdown" in the
/// metrics series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlushReason {
    /// Count threshold (`batch_max_messages`) reached.
    Count,
    /// Serialized-byte threshold (`batch_max_bytes`) reached.
    Bytes,
    /// Operator-driven drain — every remaining entry flushed regardless
    /// of thresholds. Used for shutdown and any future time-based
    /// flush.
    Drain,
}

impl FlushReason {
    /// Stable string label for metrics. Operators dashboard against
    /// these tokens — do not rename without updating every alert that
    /// filters on `reason=…`.
    // justification: only read from the `metrics`-gated `batches_flushed`
    // counter call site in publisher.rs, so builds with metrics disabled
    // never reach this method. The variants themselves remain reachable
    // because the state machine constructs them unconditionally; only
    // the label-string rendering is metrics-only.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Bytes => "bytes",
            Self::Drain => "drain",
        }
    }
}

/// A coalesced flush payload ready to be framed and sent.
#[derive(Debug)]
pub(crate) struct FlushPayload {
    pub(crate) entries: Vec<BatchEntry>,
    // justification: read by the `metrics`-gated `batches_flushed` label
    // at the publisher call site; builds without `metrics` never read it
    // but the state machine still needs to carry the classification so
    // the metric remains the single reshapeable surface.
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub(crate) reason: FlushReason,
}

impl FlushPayload {
    /// Serialized single-message bodies, in insertion order. Feed
    /// directly to [`crate::payload::render_batch`].
    pub(crate) fn bodies(&self) -> Vec<Bytes> {
        self.entries.iter().map(|e| e.body.clone()).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// In-memory accumulator for per-target batching.
#[derive(Debug)]
pub(crate) struct Batcher {
    pending: Vec<BatchEntry>,
    /// Running sum of buffered `body.len()`. Does *not* include the
    /// batch-framing overhead (JSON-array commas / NDJSON newlines);
    /// those are added by `render_batch` after flush.
    pending_bytes: usize,
    max_messages: usize,
    max_bytes: usize,
}

impl Batcher {
    /// Construct a batcher with the two flush thresholds. The caller
    /// is responsible for enforcing the `batch_max_messages >= 2` and
    /// `batch_max_bytes >= 1 KiB` validation via
    /// [`crate::config::HttpConfig::validate`].
    pub(crate) fn new(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            pending: Vec::new(),
            pending_bytes: 0,
            max_messages,
            max_bytes,
        }
    }

    /// Current number of buffered entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.pending.len()
    }

    /// Current buffered bytes (pre-framing).
    #[cfg(test)]
    pub(crate) fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Whether the batcher is currently empty (no buffered entries).
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Buffer one serialized message and, if a threshold is now met,
    /// return a [`FlushPayload`] containing *every* buffered entry
    /// (including the just-pushed one). Otherwise returns `None`.
    ///
    /// Thresholds are checked **after** the insert so a single message
    /// that on its own crosses `max_bytes` is still flushed (rather
    /// than sitting forever because it alone exceeds the cap). The
    /// count-trigger and bytes-trigger are evaluated in that order so
    /// a batch that simultaneously hits both limits is labelled
    /// `Count` — the more specific trigger.
    pub(crate) fn push(
        &mut self,
        body: Bytes,
        permit: Option<Arc<BackpressurePermit>>,
    ) -> Option<FlushPayload> {
        let body_len = body.len();
        self.pending.push(BatchEntry { body, permit });
        self.pending_bytes += body_len;

        if self.pending.len() >= self.max_messages {
            return Some(self.take(FlushReason::Count));
        }
        if self.pending_bytes >= self.max_bytes {
            return Some(self.take(FlushReason::Bytes));
        }
        None
    }

    /// Flush every buffered entry regardless of thresholds. Used for
    /// drain-on-shutdown and (future) time-based flush.
    ///
    /// Returns `None` when the batcher is empty — the caller does not
    /// need to issue an HTTP request for zero messages.
    pub(crate) fn drain(&mut self) -> Option<FlushPayload> {
        if self.pending.is_empty() {
            return None;
        }
        Some(self.take(FlushReason::Drain))
    }

    fn take(&mut self, reason: FlushReason) -> FlushPayload {
        let entries = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        FlushPayload { entries, reason }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use bytes::Bytes;

    use super::*;

    #[test]
    fn push_below_thresholds_returns_none_and_buffers() {
        let mut b = Batcher::new(5, 1024);
        assert!(b.is_empty());
        let out = b.push(Bytes::from_static(b"a"), None);
        assert!(out.is_none());
        assert_eq!(b.len(), 1);
        assert_eq!(b.pending_bytes(), 1);
    }

    #[test]
    fn push_count_threshold_triggers_count_flush() {
        let mut b = Batcher::new(3, 10 * 1024);
        assert!(b.push(Bytes::from_static(b"x"), None).is_none());
        assert!(b.push(Bytes::from_static(b"y"), None).is_none());
        let flush = b
            .push(Bytes::from_static(b"z"), None)
            .expect("third push must flush");
        assert_eq!(flush.reason, FlushReason::Count);
        assert_eq!(flush.len(), 3);
        assert!(b.is_empty(), "batcher drains on flush");
        assert_eq!(b.pending_bytes(), 0);
    }

    #[test]
    fn push_bytes_threshold_triggers_bytes_flush() {
        let mut b = Batcher::new(100, 16);
        assert!(b.push(Bytes::from_static(b"0123456"), None).is_none());
        // Total after this push: 7 + 10 = 17 > 16 -> bytes flush.
        let flush = b
            .push(Bytes::from_static(b"abcdefghij"), None)
            .expect("bytes cap must flush");
        assert_eq!(flush.reason, FlushReason::Bytes);
        assert_eq!(flush.len(), 2);
    }

    #[test]
    fn count_threshold_wins_when_both_hit_simultaneously() {
        // max_messages=2, max_bytes=6; second push brings both to their
        // caps at once. Count is the more specific trigger, so it wins.
        let mut b = Batcher::new(2, 6);
        assert!(b.push(Bytes::from_static(b"aaa"), None).is_none());
        let flush = b
            .push(Bytes::from_static(b"bbb"), None)
            .expect("simultaneous cap hit must flush");
        assert_eq!(flush.reason, FlushReason::Count);
        assert_eq!(flush.len(), 2);
    }

    #[test]
    fn single_oversized_message_still_flushes_via_bytes() {
        // One push whose body alone exceeds max_bytes: must flush rather
        // than park indefinitely waiting for more messages.
        let mut b = Batcher::new(100, 8);
        let flush = b
            .push(Bytes::from_static(b"xxxxxxxxxxxxxxxx"), None)
            .expect("lone-oversized push must flush");
        assert_eq!(flush.reason, FlushReason::Bytes);
        assert_eq!(flush.len(), 1);
    }

    #[test]
    fn drain_returns_none_when_empty() {
        let mut b = Batcher::new(5, 1024);
        assert!(b.drain().is_none());
    }

    #[test]
    fn drain_flushes_remaining_entries_with_drain_reason() {
        let mut b = Batcher::new(10, 1024);
        assert!(b.push(Bytes::from_static(b"a"), None).is_none());
        assert!(b.push(Bytes::from_static(b"b"), None).is_none());
        let flush = b.drain().expect("non-empty drain must yield payload");
        assert_eq!(flush.reason, FlushReason::Drain);
        assert_eq!(flush.len(), 2);
        assert!(b.is_empty());
    }

    #[test]
    fn flush_payload_bodies_preserve_insertion_order() {
        let mut b = Batcher::new(3, 1024);
        let _ = b.push(Bytes::from_static(b"first"), None);
        let _ = b.push(Bytes::from_static(b"second"), None);
        let flush = b.push(Bytes::from_static(b"third"), None).unwrap();
        let bodies = flush.bodies();
        assert_eq!(bodies.len(), 3);
        assert_eq!(&bodies[0][..], b"first");
        assert_eq!(&bodies[1][..], b"second");
        assert_eq!(&bodies[2][..], b"third");
    }

    #[test]
    fn flush_reason_as_str_is_stable_metric_label() {
        // Operators alert against these tokens — pin the exact strings.
        assert_eq!(FlushReason::Count.as_str(), "count");
        assert_eq!(FlushReason::Bytes.as_str(), "bytes");
        assert_eq!(FlushReason::Drain.as_str(), "drain");
    }

    #[test]
    fn pending_bytes_tracks_only_raw_body_sizes_not_framing_overhead() {
        // The batcher must not pre-account for JSON-array commas or
        // NDJSON newlines — those are the renderer's concern. A
        // regression that added (n-1) to pending_bytes would flip the
        // bytes threshold early on ~1 KiB boundaries.
        let mut b = Batcher::new(10, 1024);
        let _ = b.push(Bytes::from_static(b"abcde"), None);
        let _ = b.push(Bytes::from_static(b"fghij"), None);
        assert_eq!(b.pending_bytes(), 10);
    }

    #[test]
    fn buffered_permit_keeps_gate_reserved_until_flush_payload_drops() {
        use rustgate_resilience::backpressure::BackpressureGate;

        let gate = BackpressureGate::new(1_000_000);
        let mut b = Batcher::new(2, 1_000_000);

        // First push buffers below thresholds; the permit rides along in
        // the entry, so the gate must keep counting its reserved bytes.
        let permit = Arc::new(gate.acquire(100));
        assert!(b.push(Bytes::from_static(b"a"), Some(permit)).is_none());
        assert_eq!(
            gate.current(),
            100,
            "buffered entry must keep its reservation alive"
        );

        // Second push crosses the count threshold and yields the flush
        // payload. The reservation is still held — the flush owns the
        // permit until it is dropped after the (would-be) send.
        let permit2 = Arc::new(gate.acquire(50));
        let flush = b
            .push(Bytes::from_static(b"b"), Some(permit2))
            .expect("count threshold must flush");
        assert_eq!(
            gate.current(),
            150,
            "flush payload still holds both reservations before drop"
        );

        // Dropping the flush payload (post-send) releases every retained
        // reservation — the gate returns to zero.
        drop(flush);
        assert_eq!(
            gate.current(),
            0,
            "dropping the flush payload must release all buffered reservations"
        );
    }
}
