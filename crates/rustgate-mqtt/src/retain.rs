// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! In-memory MQTT retained-message store.
//!
//! Implements the MQTT 3.1.1 §3.3.1 / 5.0 §3.3.1.3 retain semantics: when a
//! `PUBLISH` arrives with `retain=1` the broker stores the payload keyed by
//! topic; when a client `SUBSCRIBE`s to a matching filter the broker
//! delivers the stored payload immediately, with the retain flag set on
//! the wire so the client can distinguish a fresh publication from a
//! replay.
//!
//! ## Storage
//!
//! Single in-memory `HashMap<topic, RetainedMessage>` guarded by a
//! `parking_lot::Mutex`. Retain only stores the **last** message per
//! topic (newer publishes overwrite older ones), so the working-set size
//! is bounded by the number of distinct retained topics — typically tiny
//! compared with the message rate.
//!
//! ## Clear-on-empty-payload
//!
//! Per MQTT spec §3.3.1.3, a `PUBLISH` with `retain=1` AND a zero-byte
//! payload removes the retained message for that topic. This module
//! implements that contract via [`RetainStore::publish`] returning the
//! `Cleared` variant when an empty payload is observed.
//!
//! ## Authorization
//!
//! The store itself is authorization-agnostic — group membership is
//! checked at the SUBSCRIBE call site (in `session::handle_subscribe_*`)
//! before delivery. The store only filters by topic-vs-filter pattern
//! match; downstream code adds the per-group ACL check on top.
//!
//! ## Persistence
//!
//! Process-local only. Restarts lose the retained set. MQTT spec does
//! not require durability for retain, and the typical operational
//! pattern (publishers re-send retained "last-known-value" on connect)
//! keeps the cache populated under normal traffic.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use mqttbytes::QoS;
use parking_lot::Mutex;

use crate::topic;

/// A single retained message held by [`RetainStore`].
///
/// Carries the minimum fields needed to reconstruct an outbound `PUBLISH`
/// packet on a subsequent `SUBSCRIBE`: the payload and the QoS the
/// publisher requested. Payload is `Bytes` so cloning into the per-
/// subscriber outbound packet is cheap (atomic refcount bump, no copy).
#[derive(Debug, Clone)]
pub(crate) struct RetainedMessage {
    /// Original PUBLISH payload. Stored verbatim — the broker does not
    /// inspect the bytes for retain purposes.
    pub(crate) payload: Bytes,
    /// QoS the publisher sent the message with. The replay to a new
    /// subscriber must downgrade to `min(publisher_qos, subscriber_qos)`
    /// per MQTT spec, which the SUBSCRIBE handler does at delivery time.
    pub(crate) qos: QoS,
}

/// Outcome of a [`RetainStore::publish`] call. Surfaced for observability
/// (audit / metrics) — the storage layer itself does not care which
/// branch fired, but the call site can record "X retained messages
/// stored, Y cleared, Z passthrough" without re-inspecting the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetainOutcome {
    /// `retain=1` AND non-empty payload → message stored under `topic`.
    Stored,
    /// `retain=1` AND empty payload → MQTT spec `Clear` semantics:
    /// any existing entry for `topic` is removed.
    Cleared,
    /// `retain=0` → no store-side effect; storage is a passthrough.
    /// Returned so the caller can branch on the retain bit without
    /// re-reading the publish header.
    Passthrough,
}

/// Process-local retained-message cache, shared across all MQTT
/// sessions on a single broker.
///
/// Constructed once by [`crate::server::MqttServer::run`] and threaded
/// through [`crate::session::handle_mqtt_session`] into the read loop.
/// Internally synchronised — readers and writers share `Arc<Self>`.
#[derive(Debug, Default)]
pub(crate) struct RetainStore {
    inner: Mutex<HashMap<String, RetainedMessage>>,
}

impl RetainStore {
    /// Build a fresh empty store, wrapped in `Arc` for cheap fan-out
    /// to per-connection session tasks.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a PUBLISH against the store, honoring MQTT retain
    /// semantics:
    ///
    /// - `retain == false` → no-op, returns [`RetainOutcome::Passthrough`].
    /// - `retain == true && payload.is_empty()` → remove any existing
    ///   entry for `topic`, returns [`RetainOutcome::Cleared`].
    /// - `retain == true && !payload.is_empty()` → overwrite the entry
    ///   for `topic` with the new payload + qos, returns
    ///   [`RetainOutcome::Stored`].
    pub(crate) fn publish(
        &self,
        topic: &str,
        payload: &Bytes,
        qos: QoS,
        retain: bool,
    ) -> RetainOutcome {
        if !retain {
            return RetainOutcome::Passthrough;
        }
        let mut map = self.inner.lock();
        if payload.is_empty() {
            let _ = map.remove(topic);
            RetainOutcome::Cleared
        } else {
            let _ = map.insert(
                topic.to_string(),
                RetainedMessage {
                    payload: payload.clone(),
                    qos,
                },
            );
            RetainOutcome::Stored
        }
    }

    /// Return every retained `(topic, message)` pair whose `topic`
    /// matches `subscribe_filter` after both are translated into the
    /// same coordinate space by stripping `topic_prefix`.
    ///
    /// `topic_prefix` mirrors `MqttServerConfig::topic_prefix`: when
    /// the broker is namespaced, both the published topic on the
    /// retain side and the subscriber's filter on the wire carry the
    /// prefix; we strip it from both before delegating to
    /// [`topic::filter_matches`] so the wildcard expansion happens in
    /// the group-name coordinate space.
    ///
    /// Returns an owned `Vec` because the caller needs to relinquish
    /// the mutex before doing any async I/O — holding a
    /// `parking_lot::Mutex` across an `.await` is the workspace
    /// "deadlock footgun" pattern this crate already lints against.
    /// Each `RetainedMessage` is a cheap clone (`Bytes` + `QoS`).
    pub(crate) fn matching(
        &self,
        subscribe_filter: &str,
        topic_prefix: Option<&str>,
    ) -> Vec<(String, RetainedMessage)> {
        let stripped_filter = match topic_prefix {
            Some(p) => match subscribe_filter.strip_prefix(p) {
                Some(s) => s,
                // Filter outside the broker prefix: no retained topic
                // can match either, so short-circuit empty.
                None => return Vec::new(),
            },
            None => subscribe_filter,
        };
        let map = self.inner.lock();
        map.iter()
            .filter_map(|(topic, msg)| {
                let topic_for_match = match topic_prefix {
                    Some(p) => topic.strip_prefix(p)?,
                    None => topic.as_str(),
                };
                if topic::filter_matches(stripped_filter, topic_for_match) {
                    Some((topic.clone(), msg.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Number of distinct retained topics. Used for metrics and tests.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn payload(s: &[u8]) -> Bytes {
        Bytes::copy_from_slice(s)
    }

    #[test]
    fn publish_with_retain_false_is_passthrough() {
        let store = RetainStore::new();
        let outcome = store.publish("alpha", &payload(b"hi"), QoS::AtMostOnce, false);
        assert_eq!(outcome, RetainOutcome::Passthrough);
        assert_eq!(store.len(), 0, "passthrough must not persist");
    }

    #[test]
    fn publish_with_retain_and_payload_stores() {
        let store = RetainStore::new();
        let outcome = store.publish("alpha", &payload(b"hi"), QoS::AtMostOnce, true);
        assert_eq!(outcome, RetainOutcome::Stored);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn publish_with_retain_and_empty_payload_clears_existing() {
        // MQTT 5.0 §3.3.1.3 — a retained PUBLISH with zero-byte payload
        // removes the retained entry for that topic.
        let store = RetainStore::new();
        let _ = store.publish("alpha", &payload(b"hi"), QoS::AtMostOnce, true);
        assert_eq!(store.len(), 1);
        let outcome = store.publish("alpha", &Bytes::new(), QoS::AtMostOnce, true);
        assert_eq!(outcome, RetainOutcome::Cleared);
        assert_eq!(store.len(), 0, "empty retain payload must clear entry");
    }

    #[test]
    fn publish_with_retain_and_empty_payload_on_unknown_topic_is_clear() {
        // Spec edge case: a clear on a topic that has no prior
        // retained entry must not panic and must not invent one.
        let store = RetainStore::new();
        let outcome = store.publish("unknown", &Bytes::new(), QoS::AtMostOnce, true);
        assert_eq!(outcome, RetainOutcome::Cleared);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn publish_overwrites_previous_entry() {
        // Newer retained message replaces older one on the same topic;
        // the broker only keeps the last value, not a history.
        let store = RetainStore::new();
        let _ = store.publish("alpha", &payload(b"old"), QoS::AtMostOnce, true);
        let _ = store.publish("alpha", &payload(b"new"), QoS::AtLeastOnce, true);
        assert_eq!(store.len(), 1);
        let matches = store.matching("alpha", None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.payload, payload(b"new"));
        assert_eq!(matches[0].1.qos, QoS::AtLeastOnce);
    }

    #[test]
    fn matching_returns_exact_topic_match() {
        let store = RetainStore::new();
        let _ = store.publish("alpha", &payload(b"x"), QoS::AtMostOnce, true);
        let matches = store.matching("alpha", None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "alpha");
    }

    #[test]
    fn matching_supports_single_level_wildcard() {
        let store = RetainStore::new();
        let _ = store.publish("fleet/red/pos", &payload(b"r"), QoS::AtMostOnce, true);
        let _ = store.publish("fleet/blue/pos", &payload(b"b"), QoS::AtMostOnce, true);
        let _ = store.publish("fleet/red/cmd", &payload(b"c"), QoS::AtMostOnce, true);
        let mut matches = store.matching("fleet/+/pos", None);
        matches.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].0, "fleet/blue/pos");
        assert_eq!(matches[1].0, "fleet/red/pos");
    }

    #[test]
    fn matching_supports_multi_level_wildcard() {
        let store = RetainStore::new();
        let _ = store.publish("fleet/red/pos", &payload(b"r"), QoS::AtMostOnce, true);
        let _ = store.publish("fleet/red/cmd", &payload(b"c"), QoS::AtMostOnce, true);
        let _ = store.publish("other", &payload(b"o"), QoS::AtMostOnce, true);
        let matches = store.matching("fleet/#", None);
        assert_eq!(matches.len(), 2, "fleet/# must match two, exclude `other`");
    }

    #[test]
    fn matching_strips_topic_prefix_consistently() {
        // With a broker prefix, both stored topics and the subscribe
        // filter carry it on the wire; the matcher strips both before
        // delegating to filter_matches so the wildcard expansion
        // happens in the group-name coordinate space.
        let store = RetainStore::new();
        let prefix = Some("rustgate/");
        let _ = store.publish("rustgate/fleet/red", &payload(b"r"), QoS::AtMostOnce, true);
        let _ = store.publish("rustgate/fleet/blue", &payload(b"b"), QoS::AtMostOnce, true);
        let matches = store.matching("rustgate/fleet/+", prefix);
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|(t, _)| t == "rustgate/fleet/red"));
        assert!(matches.iter().any(|(t, _)| t == "rustgate/fleet/blue"));
    }

    #[test]
    fn matching_with_filter_outside_prefix_returns_empty() {
        // Defensive: a subscribe filter that does not start with the
        // broker prefix cannot match any retained topic. Short-circuit
        // empty rather than risk a misleading wildcard expansion.
        let store = RetainStore::new();
        let _ = store.publish("rustgate/fleet/red", &payload(b"r"), QoS::AtMostOnce, true);
        let matches = store.matching("other/fleet/+", Some("rustgate/"));
        assert!(matches.is_empty());
    }

    #[test]
    fn matching_returns_empty_on_no_matches() {
        let store = RetainStore::new();
        let _ = store.publish("alpha", &payload(b"x"), QoS::AtMostOnce, true);
        assert!(store.matching("bravo", None).is_empty());
    }

    #[test]
    fn matching_preserves_qos_in_retained_message() {
        let store = RetainStore::new();
        let _ = store.publish("alpha", &payload(b"x"), QoS::AtLeastOnce, true);
        let matches = store.matching("alpha", None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.qos, QoS::AtLeastOnce);
    }
}
