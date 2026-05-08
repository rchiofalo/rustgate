// Copyright © 2026 Roberto Chiofalo.

//! In-memory catalog of video streams advertised via CoT `b-i-v` events.
//!
//! Closes #862. ATAK / WinTAK clients announce a video feed by sending a
//! Cursor-on-Target event with `type="b-i-v-…"` whose `<detail>` element
//! carries a `<__video url="…"/>` block (the URL of the RTSP / RTMP / HLS
//! stream the operator can connect to) and an optional `<sensor …/>`
//! block describing the sensor's field-of-view, azimuth, elevation, and
//! range. The catalog inspects every routed message that looks like a
//! `b-i-v` event, parses just the detail block needed to populate a
//! catalog entry, and keeps the latest entry per UID.
//!
//! MVP scope:
//! * In-memory only — no on-disk persistence.
//! * Lazy TTL eviction — entries time out at `received_at + ttl` and
//!   are filtered out on read instead of via a background sweep task.
//!   This keeps the surface free of additional `tokio::spawn`s and
//!   sidesteps the lifecycle that a polling task would need.
//! * One `GET /api/video/streams` endpoint that returns the current
//!   live snapshot as JSON.
//!
//! The catalog is wired in by the server binary: it installs a
//! [`Router::set_on_routed`](rustgate_router::Router::set_on_routed)
//! callback that funnels every routed message through
//! [`VideoStreamCatalog::observe`], and it registers the HTTP handler
//! returned by [`handler`] under the existing `mgmt_api_slot` /
//! `acl_api_slot` dispatch ladder in [`crate::server`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};
use rustgate_core::message::{MessageType, RoutableMessage};
use serde::Serialize;

/// Single video-stream entry held in the catalog.
///
/// Fields with `Option` are rendered as JSON `null` when the source
/// CoT event omitted them — operators consuming `/api/video/streams`
/// can lean on the field's presence as the only signal.
#[derive(Debug, Clone, Serialize)]
pub struct VideoEntry {
    /// CoT event UID (e.g. `"VIDEO-MQ45"`). Catalog-unique.
    pub uid: String,
    /// CN of the client that originated the event.
    pub source_cn: String,
    /// CoT event type as it appeared on the wire (e.g. `"b-i-v-r"`).
    pub event_type: String,
    /// Stream URL extracted from `<__video url="…"/>` (may be RTSP, RTMP,
    /// HLS, or any other scheme — the catalog is transport-agnostic).
    pub stream_url: Option<String>,
    /// Sensor field-of-view in degrees (`<sensor fov="…"/>`).
    pub sensor_fov: Option<f64>,
    /// Sensor azimuth in degrees true (`<sensor azimuth="…"/>`).
    pub sensor_azimuth: Option<f64>,
    /// Sensor elevation in degrees (`<sensor elevation="…"/>`).
    pub sensor_elevation: Option<f64>,
    /// Latitude of the source platform (degrees, WGS-84).
    pub lat: Option<f64>,
    /// Longitude of the source platform (degrees, WGS-84).
    pub lon: Option<f64>,
    /// Wall-clock SystemTime at which `received_at + ttl` lapses. When
    /// the source CoT event omits a TTL, the entry never expires until
    /// it is overwritten by a newer event with the same UID.
    #[serde(skip)]
    pub expires_at: Option<SystemTime>,
}

/// In-memory catalog of [`VideoEntry`] keyed by event UID.
///
/// Cheap to clone (`Arc<RwLock<…>>`) so multiple subsystems may hold a
/// reference without coordinating ownership. The router callback path
/// takes a write lock for one HashMap insert per `b-i-v` event; the
/// HTTP handler takes a read lock just long enough to snapshot the live
/// (non-expired) entries into a serialized JSON array.
#[derive(Debug, Default, Clone)]
pub struct VideoStreamCatalog {
    inner: Arc<RwLock<HashMap<String, VideoEntry>>>,
}

impl VideoStreamCatalog {
    /// Construct an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inspect a routed message and, when it looks like a CoT `b-i-v`
    /// video event, extract the catalog metadata and store it under
    /// the event UID. Messages that are not `b-i-v` shaped are ignored
    /// — this keeps the routing-callback hot path bounded to a single
    /// `MessageType`-tag check + a `starts_with` test on the type
    /// string.
    pub fn observe(&self, msg: &RoutableMessage) {
        let event_type = match &msg.metadata.message_type {
            MessageType::Other(s) if s.starts_with("b-i-v") => s.clone(),
            _ => return,
        };
        // Best-effort parse — any XML failure leaves the catalog
        // unchanged so a malformed event from one client cannot poison
        // the entire catalog. The router has already admitted the
        // message; surfacing a parse error here would not be
        // actionable.
        let Some(entry) = parse_video_detail(msg, &event_type) else {
            tracing::debug!(
                event_type = %event_type,
                "video catalog: skipped malformed b-i-v event"
            );
            return;
        };
        let uid = entry.uid.clone();
        if let Ok(mut guard) = self.inner.write() {
            let _ = guard.insert(uid, entry);
        }
    }

    /// Snapshot the live (non-expired) entries.
    ///
    /// Performs lazy TTL eviction: entries whose `expires_at` is in the
    /// past are filtered out of the snapshot AND dropped from the
    /// underlying map. This avoids the bookkeeping cost of a periodic
    /// sweep task at the price of one extra map clean-up per snapshot
    /// — the catalog is small (one entry per video-emitting client)
    /// and snapshotted by an operator-driven HTTP request, so the
    /// trade-off is favourable for the MVP.
    pub fn snapshot(&self) -> Vec<VideoEntry> {
        let now = SystemTime::now();
        // Acquire write lock so we can prune expired entries lazily.
        let Ok(mut guard) = self.inner.write() else {
            return Vec::new();
        };
        guard.retain(|_, entry| match entry.expires_at {
            Some(deadline) => deadline > now,
            None => true,
        });
        guard.values().cloned().collect()
    }
}

/// Parse the CoT `<detail>` payload to fill a [`VideoEntry`].
///
/// Returns `None` when the inbound payload is not parseable XML or
/// when the event lacks a UID — the rest of the fields are optional
/// and are recorded as `None` when absent from the wire.
fn parse_video_detail(msg: &RoutableMessage, event_type: &str) -> Option<VideoEntry> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(msg.payload.as_ref());
    reader.config_mut().trim_text(true);

    let mut uid: Option<String> = None;
    let mut stream_url = None;
    let mut sensor_fov = None;
    let mut sensor_azimuth = None;
    let mut sensor_elevation = None;
    let mut lat = None;
    let mut lon = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.name().as_ref() {
                b"event" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"uid" {
                            uid = Some(String::from_utf8_lossy(&attr.value).into_owned());
                        }
                    }
                }
                b"point" => {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"lat" => lat = parse_attr_f64(&attr.value),
                            b"lon" => lon = parse_attr_f64(&attr.value),
                            _ => {}
                        }
                    }
                }
                b"__video" | b"video" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"url" {
                            stream_url = Some(String::from_utf8_lossy(&attr.value).into_owned());
                        }
                    }
                }
                b"sensor" => {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"fov" => sensor_fov = parse_attr_f64(&attr.value),
                            b"azimuth" => sensor_azimuth = parse_attr_f64(&attr.value),
                            b"elevation" => sensor_elevation = parse_attr_f64(&attr.value),
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }

    let uid = uid?;
    let expires_at = msg
        .metadata
        .ttl
        .and_then(|ttl| msg.metadata.received_at.checked_add(ttl));

    Some(VideoEntry {
        uid,
        source_cn: msg.source.cn.to_string(),
        event_type: event_type.to_string(),
        stream_url,
        sensor_fov,
        sensor_azimuth,
        sensor_elevation,
        lat,
        lon,
        expires_at,
    })
}

fn parse_attr_f64(value: &[u8]) -> Option<f64> {
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// Build a hyper response handler closure for `GET /api/video/streams`.
///
/// Returns `None` for any path / method that does not match so the
/// caller can fall through to the next dispatcher. The handler shape
/// mirrors the existing `AclApiHandler` (sync `Fn` — the catalog read
/// path is non-blocking).
pub fn handler(
    catalog: Arc<VideoStreamCatalog>,
) -> impl Fn(&Method, &str, &[u8]) -> Option<Response<Full<Bytes>>> + Send + Sync + 'static {
    move |method: &Method, path: &str, _body: &[u8]| -> Option<Response<Full<Bytes>>> {
        if path != "/api/video/streams" {
            return None;
        }
        if method != Method::GET {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("allow", "GET")
                .body(Full::new(Bytes::from("method not allowed")))
                .ok();
        }
        let entries = catalog.snapshot();
        let body = serde_json::to_vec(&entries).ok()?;
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .ok()
    }
}

/// Convenience: construct the `OnRouted` callback that funnels routed
/// messages into the supplied catalog.
///
/// Lives here rather than at the server binary's wiring site so all
/// the video-specific glue stays in one module. The callback is
/// `Send + Sync` because [`VideoStreamCatalog`] is `Arc`-cloned and
/// the inner `RwLock` is itself `Send + Sync`.
pub fn router_callback(catalog: Arc<VideoStreamCatalog>) -> rustgate_router::OnRouted {
    Arc::new(move |msg: Arc<RoutableMessage>| {
        catalog.observe(msg.as_ref());
    })
}

/// Default TTL applied to entries whose source CoT event omitted a
/// `start`/`stale` pair. Chosen at five minutes — long enough that an
/// operator polling once a minute reliably sees the entry, short
/// enough that a stale stream falls out of the catalog before it
/// becomes confusingly long-lived. Unused inside the module today
/// (the parser preserves the on-wire `None`); exposed for callers
/// that want to apply a project-wide default.
pub const DEFAULT_VIDEO_TTL: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use rustgate_core::identity::Identity;
    use rustgate_core::message::{Destination, Metadata};

    use super::*;

    fn synth_msg(payload: &str, event_type: &str, ttl: Option<Duration>) -> RoutableMessage {
        let identity = Identity::plaintext("alpha".to_string(), BTreeSet::new()).unwrap();
        let mut meta = Metadata::new(
            SystemTime::now(),
            "tcp".to_string(),
            MessageType::Other(event_type.to_string()),
        );
        if let Some(t) = ttl {
            meta = meta.with_ttl(t);
        }
        RoutableMessage {
            source: identity,
            destination: Destination::Broadcast,
            payload: Bytes::from(payload.to_string()),
            metadata: meta,
        }
    }

    #[test]
    fn observe_inserts_b_i_v_event() {
        let catalog = VideoStreamCatalog::new();
        let xml = r#"<event uid="VID-1" type="b-i-v-r"><point lat="35.0" lon="-100.0" hae="100"/><detail><__video url="rtsp://1.2.3.4/stream"/><sensor fov="42.5" azimuth="180.0" elevation="-15.0"/></detail></event>"#;
        let msg = synth_msg(xml, "b-i-v-r", None);
        catalog.observe(&msg);
        let snap = catalog.snapshot();
        assert_eq!(snap.len(), 1);
        let e = &snap[0];
        assert_eq!(e.uid, "VID-1");
        assert_eq!(e.event_type, "b-i-v-r");
        assert_eq!(e.stream_url.as_deref(), Some("rtsp://1.2.3.4/stream"));
        assert_eq!(e.sensor_fov, Some(42.5));
        assert_eq!(e.sensor_azimuth, Some(180.0));
        assert_eq!(e.sensor_elevation, Some(-15.0));
        assert_eq!(e.lat, Some(35.0));
        assert_eq!(e.lon, Some(-100.0));
    }

    #[test]
    fn observe_ignores_non_b_i_v_messages() {
        let catalog = VideoStreamCatalog::new();
        let xml = r#"<event uid="X" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#;
        let msg = synth_msg(xml, "a-f-G", None);
        catalog.observe(&msg);
        assert!(catalog.snapshot().is_empty());
    }

    #[test]
    fn observe_overwrites_same_uid() {
        let catalog = VideoStreamCatalog::new();
        let xml1 =
            r#"<event uid="V" type="b-i-v"><detail><__video url="rtsp://a"/></detail></event>"#;
        let xml2 =
            r#"<event uid="V" type="b-i-v"><detail><__video url="rtsp://b"/></detail></event>"#;
        catalog.observe(&synth_msg(xml1, "b-i-v", None));
        catalog.observe(&synth_msg(xml2, "b-i-v", None));
        let snap = catalog.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].stream_url.as_deref(), Some("rtsp://b"));
    }

    #[test]
    fn snapshot_evicts_expired_entries() {
        let catalog = VideoStreamCatalog::new();
        let xml = r#"<event uid="VID-EXP" type="b-i-v"><detail><__video url="rtsp://x"/></detail></event>"#;
        // 1ns TTL — guaranteed expired by the time we snapshot.
        catalog.observe(&synth_msg(xml, "b-i-v", Some(Duration::from_nanos(1))));
        std::thread::sleep(Duration::from_millis(10));
        assert!(catalog.snapshot().is_empty());
    }

    #[tokio::test]
    async fn handler_returns_json_array() {
        use http_body_util::BodyExt;
        let catalog = Arc::new(VideoStreamCatalog::new());
        let xml =
            r#"<event uid="V" type="b-i-v"><detail><__video url="rtsp://a"/></detail></event>"#;
        catalog.observe(&synth_msg(xml, "b-i-v", None));
        let h = handler(Arc::clone(&catalog));
        let resp = h(&Method::GET, "/api/video/streams", b"").expect("handler matched");
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn handler_rejects_non_get() {
        let catalog = Arc::new(VideoStreamCatalog::new());
        let h = handler(catalog);
        let resp = h(&Method::POST, "/api/video/streams", b"").expect("matched");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn handler_returns_none_for_other_paths() {
        let catalog = Arc::new(VideoStreamCatalog::new());
        let h = handler(catalog);
        assert!(h(&Method::GET, "/api/other", b"").is_none());
    }
}
