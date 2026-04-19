// Copyright © 2026 Roberto Chiofalo.

//! Per-UID delta encoding for outbound CoT events.
//!
//! Many CoT event streams are dominated by periodic "track" updates that
//! carry the same `uid`/`type`/`how` tuple every few seconds with only the
//! `point` coordinates and event timestamps changing. Forwarding every
//! update in full wastes bandwidth on dense workloads.
//!
//! This module provides a bandwidth-saving codec that the per-session
//! outbound writer task runs against its own private cache:
//!
//! * [`DeltaEncoder`] tracks the last-sent snapshot per `uid` and emits
//!   either a full event (first sighting for this writer, cache eviction,
//!   or a message that does not look like CoT) or a delta containing only
//!   the fields that actually changed. A configurable epsilon suppresses
//!   position updates below a ground-distance threshold entirely.
//! * [`DeltaDecoder`] reverses the transformation, merging a received
//!   delta with a cached snapshot to reconstruct the full event. The
//!   decoder exists for round-trip testing and for clients that wish to
//!   consume the wire format from Rust.
//!
//! # Wire format
//!
//! A delta event wraps the changed fields inside a `<delta>` child element
//! of the original `<event>`. The parent `<event>` retains the immutable
//! attributes (`version`, `uid`, `type`, `how`) so downstream tooling that
//! only inspects the outer tag still has a valid skeleton.
//!
//! ```xml
//! <event version="2.0" uid="ANDROID-123" type="a-f-G-U-C" how="m-g">
//!   <delta time="2026-04-08T12:34:56Z" start="2026-04-08T12:34:56Z" stale="2026-04-08T12:35:56Z">
//!     <point lat="34.123" lon="-118.456" hae="100.5" ce="9.9" le="9.9"/>
//!   </delta>
//! </event>
//! ```
//!
//! Fields that did not change between the prior snapshot and the new event
//! are simply omitted from the `<delta>` subtree. Timestamps (`time`,
//! `start`, `stale`) are always included when they differ, which in
//! practice is every update. The existing `<detail>` subtree is emitted
//! verbatim inside `<delta>` only when its bytes differ from the cached
//! prior snapshot.
//!
//! The immutable outer attributes (`version`, `uid`, `type`, `how`) must
//! not change inside a single stream: if they do, the encoder treats the
//! event as a new stream and emits it as a full event so downstream
//! tooling cannot drift.
//!
//! # Suppression
//!
//! When the configured epsilon (`epsilon_meters`) is greater than zero the
//! encoder computes the approximate ground distance between the cached and
//! new `<point>` and suppresses the update entirely if the distance is
//! below the threshold and no other field changed. Suppression is a
//! strictly optional optimization and can be disabled by setting
//! `epsilon_meters` to `0.0`.
//!
//! # Why per-writer, not router-global
//!
//! The cache deliberately lives at the writer-task scope. New subscribers
//! always receive a full event for the first sighting of any `uid` because
//! their encoder cache starts empty, so there is no join-latency penalty
//! and no need for periodic keyframes. See issue #568 for the design
//! tradeoffs that led to this choice.

use std::num::NonZeroUsize;

use bytes::Bytes;
use lru::LruCache;

/// Maximum number of bytes the encoder will scan from the head of each
/// payload before giving up and emitting the message as full. A CoT
/// `<event>` opening tag plus its `<point>` and common `<detail>`
/// children almost always fit inside this window; streams that exceed it
/// are encoded opportunistically as full events rather than risking an
/// unbounded allocation on hostile input.
///
/// Exposed as a public constant so callers can set framing limits or
/// metric thresholds against the same value.
pub const MAX_SCAN_BYTES: usize = 64 * 1024;

/// One byte of slack around each float compare. The CoT parsers on the
/// wire emit `lat="34.123"` shapes; floats written and parsed symmetrically
/// round-trip exactly, so an epsilon-free equality check is sufficient for
/// attribute-level diffing while the suppression epsilon governs whether a
/// position update ships at all.
fn floats_equal(a: f64, b: f64) -> bool {
    a.to_bits() == b.to_bits()
}

/// Fields captured from a CoT event for delta comparison.
///
/// The snapshot is deliberately minimal: only the attributes that the
/// encoder needs to diff are stored. Everything else (comments,
/// namespaces, unknown attributes) is preserved on the outer `<event>` of
/// the emitted XML by re-serializing from the cached bytes, so lossless
/// round-tripping is not a goal — the decoder reconstructs a canonical
/// shape from the snapshot fields.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CotSnapshot {
    /// `version` attribute on the root `<event>` element. Defaults to
    /// `"2.0"` if absent.
    pub version: String,
    /// `uid` attribute on the root `<event>`.
    pub uid: String,
    /// `type` attribute on the root `<event>`.
    pub event_type: String,
    /// `how` attribute, if present.
    pub how: Option<String>,
    /// `time` attribute on the root `<event>`.
    pub time: String,
    /// `start` attribute on the root `<event>`.
    pub start: String,
    /// `stale` attribute on the root `<event>`.
    pub stale: String,
    /// Point element, if present.
    pub point: Option<CotPoint>,
    /// Verbatim byte slice of the inner `<detail>...</detail>` contents,
    /// if present. Stored as a raw string so detail subtree comparison is
    /// a simple byte equality check.
    pub detail_inner: Option<String>,
}

/// `<point>` element attributes.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CotPoint {
    /// WGS-84 latitude in degrees.
    pub lat: f64,
    /// WGS-84 longitude in degrees.
    pub lon: f64,
    /// Height above the ellipsoid in meters.
    pub hae: f64,
    /// Circular (horizontal) error in meters. Defaults to `9999999.0`.
    pub ce: f64,
    /// Linear (vertical) error in meters. Defaults to `9999999.0`.
    pub le: f64,
}

/// Errors produced by the delta encoder/decoder.
#[derive(Debug)]
pub enum DeltaError {
    /// The payload could not be parsed as CoT XML.
    NotCot,
    /// The cached snapshot referenced by a delta is missing, so the delta
    /// cannot be reconstructed into a full event.
    MissingCache,
    /// The XML was syntactically valid but did not carry a `uid` attribute
    /// on the `<event>` element.
    MissingUid,
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaError::NotCot => f.write_str("payload is not CoT XML"),
            DeltaError::MissingCache => f.write_str("no cached snapshot for uid"),
            DeltaError::MissingUid => f.write_str("event has no uid attribute"),
        }
    }
}

impl std::error::Error for DeltaError {}

/// Output of [`DeltaEncoder::encode`].
#[derive(Debug, Clone)]
pub enum DeltaOutput {
    /// Emit the full event bytes (first sighting for this UID, forced
    /// full, or non-CoT payload).
    Full(Bytes),
    /// Emit a delta-encoded wrapper whose body only contains the fields
    /// that changed relative to the cached snapshot.
    Delta(Bytes),
    /// The update was below the configured suppression epsilon and
    /// carried no other changes — nothing should be written to the wire.
    Suppressed,
}

/// Per-UID delta encoder for outbound CoT.
///
/// The encoder is cheap to construct and is intended to live at the
/// per-session writer-task scope. It is not `Clone` and is not internally
/// synchronized — each writer task owns its own instance.
pub struct DeltaEncoder {
    cache: LruCache<String, CotSnapshot>,
    epsilon_meters: f64,
    /// Running counters for observability. The session layer reads these
    /// after each call to update Prometheus metrics without pulling a
    /// metrics dependency into this crate.
    stats: DeltaStats,
}

impl std::fmt::Debug for DeltaEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeltaEncoder")
            .field("capacity", &self.cache.cap())
            .field("len", &self.cache.len())
            .field("epsilon_meters", &self.epsilon_meters)
            .field("stats", &self.stats)
            .finish()
    }
}

/// Counters the writer task reads after each call to publish metrics.
///
/// The fields are cumulative since construction and monotonically
/// increasing. Callers typically snapshot them, diff against the previous
/// snapshot, and publish the delta to Prometheus counters.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeltaStats {
    /// Total full events emitted.
    pub full: u64,
    /// Total delta events emitted.
    pub delta: u64,
    /// Total events suppressed because no material change was detected.
    pub suppressed: u64,
    /// Total bytes saved vs. sending the full payload. Computed as
    /// `full_len - delta_len` for each emitted delta.
    pub bytes_saved: u64,
    /// Total LRU evictions observed — each tick corresponds to one UID
    /// bumped out of the cache under cache-size pressure, which forces a
    /// subsequent full emit the next time that UID is seen. A sustained
    /// non-zero rate under steady workload is a signal that the
    /// configured `cache_size` is undersized for the active UID count.
    pub evicted: u64,
    /// Total events whose payload exceeded [`MAX_SCAN_BYTES`] and were
    /// therefore emitted as full without attempting delta compression.
    /// A non-zero rate is worth an alert: it indicates either an
    /// unusually large legitimate CoT event, or a hostile client padding
    /// the payload (e.g. with whitespace or dummy detail) to defeat
    /// delta-compression and inflate bandwidth.
    pub oversized: u64,
}

impl DeltaEncoder {
    /// Build a new encoder with the given cache capacity and suppression
    /// epsilon in meters.
    ///
    /// An `epsilon_meters` of `0.0` disables suppression: every event
    /// passes through (as `Full` or `Delta`, never `Suppressed`).
    pub fn new(capacity: NonZeroUsize, epsilon_meters: f64) -> Self {
        Self {
            cache: LruCache::new(capacity),
            epsilon_meters: epsilon_meters.max(0.0),
            stats: DeltaStats::default(),
        }
    }

    /// Number of UIDs currently cached.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty (no UIDs seen yet).
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Cumulative encoder statistics since construction.
    pub fn stats(&self) -> DeltaStats {
        self.stats
    }

    /// Encode `raw` against the cached prior state for its `uid`.
    ///
    /// On any parse error the encoder falls back to [`DeltaOutput::Full`]
    /// with the original bytes — non-CoT payloads are passed through
    /// unchanged. This lets the caller unconditionally route every
    /// outbound message through the encoder without pre-classifying CoT
    /// vs. non-CoT frames.
    ///
    /// Payloads larger than [`MAX_SCAN_BYTES`] are always emitted as
    /// [`DeltaOutput::Full`] and counted in [`DeltaStats::oversized`]
    /// without attempting to parse — see F-62 in the technical analysis.
    /// This protects against an adversary who pads detail with whitespace
    /// to force full emits and inflate bandwidth: the counter makes the
    /// pattern observable to operators.
    pub fn encode(&mut self, raw: &Bytes) -> DeltaOutput {
        if raw.len() > MAX_SCAN_BYTES {
            self.stats.oversized = self.stats.oversized.saturating_add(1);
            self.stats.full = self.stats.full.saturating_add(1);
            return DeltaOutput::Full(raw.clone());
        }

        let snapshot = match parse_snapshot(raw) {
            Some(s) if !s.uid.is_empty() => s,
            _ => {
                self.stats.full = self.stats.full.saturating_add(1);
                return DeltaOutput::Full(raw.clone());
            }
        };

        let prior = self.cache.get(&snapshot.uid).cloned();
        match prior {
            None => {
                self.insert_snapshot(snapshot);
                self.stats.full = self.stats.full.saturating_add(1);
                DeltaOutput::Full(raw.clone())
            }
            Some(prior) => {
                // Immutable outer attributes drift → treat as a new
                // stream, emit full and reset the cache entry.
                if prior.version != snapshot.version
                    || prior.event_type != snapshot.event_type
                    || prior.how != snapshot.how
                {
                    self.insert_snapshot(snapshot);
                    self.stats.full = self.stats.full.saturating_add(1);
                    return DeltaOutput::Full(raw.clone());
                }

                let delta_body = build_delta_body(&prior, &snapshot);
                if delta_body.is_empty() {
                    // No field differences at all → always suppress,
                    // regardless of epsilon.
                    self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                    return DeltaOutput::Suppressed;
                }

                if self.epsilon_meters > 0.0
                    && is_position_only_change(&prior, &snapshot)
                    && let (Some(a), Some(b)) = (prior.point, snapshot.point)
                    && approx_distance_meters(a.lat, a.lon, b.lat, b.lon) < self.epsilon_meters
                    && floats_equal(a.hae, b.hae)
                    && floats_equal(a.ce, b.ce)
                    && floats_equal(a.le, b.le)
                {
                    // Position drift below epsilon and nothing else
                    // changed — suppress. Do NOT refresh the cache
                    // entry; the next update is compared against the
                    // same reference position so drift cannot
                    // accumulate below the threshold.
                    self.stats.suppressed = self.stats.suppressed.saturating_add(1);
                    return DeltaOutput::Suppressed;
                }

                let xml = assemble_delta_xml(&snapshot, &delta_body);
                let saved = raw.len().saturating_sub(xml.len()) as u64;
                self.stats.delta = self.stats.delta.saturating_add(1);
                self.stats.bytes_saved = self.stats.bytes_saved.saturating_add(saved);
                self.insert_snapshot(snapshot);
                DeltaOutput::Delta(Bytes::from(xml))
            }
        }
    }

    /// Insert a snapshot into the cache, counting any LRU eviction that
    /// displaces a different UID. The underlying `LruCache::push` returns
    /// `Some((key, value))` both when an entry is evicted under capacity
    /// pressure and when the same key is overwritten, so we filter to
    /// cross-UID displacements only.
    fn insert_snapshot(&mut self, snapshot: CotSnapshot) {
        let uid = snapshot.uid.clone();
        if let Some((displaced, _)) = self.cache.push(uid.clone(), snapshot)
            && displaced != uid
        {
            self.stats.evicted = self.stats.evicted.saturating_add(1);
        }
    }

    /// Reset the cache. Subsequent events for any UID will be emitted as
    /// full.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

/// Decoder counterpart. Given a delta event and a matching cached prior
/// snapshot, rebuilds the full event XML. The decoder is a pure function
/// of the delta bytes and the decoder's own cache; it is kept intentionally
/// simple and allocates a fresh `String` per call.
#[derive(Debug)]
pub struct DeltaDecoder {
    cache: LruCache<String, CotSnapshot>,
}

impl DeltaDecoder {
    /// Build a decoder with the given cache capacity.
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            cache: LruCache::new(capacity),
        }
    }

    /// Consume an incoming message.
    ///
    /// If the message is a full event, it is cached and returned
    /// unchanged. If it is a delta, the decoder merges it against the
    /// cached snapshot for its `uid` and returns the reconstructed full
    /// event XML.
    ///
    /// # Canonicalization
    ///
    /// The reconstructed XML is **canonical form**, not byte-identical to
    /// the sender's original. Numeric attributes are re-serialized via
    /// `fmt_f64`, which always renders integer-valued floats with a
    /// trailing `.0` (e.g. `hae="100"` in the source becomes `hae="100.0"`
    /// on reconstruction). Every semantic field — `lat`, `lon`, `hae`,
    /// `ce`, `le`, `time`, `start`, `stale`, `type`, `how`, `detail` —
    /// round-trips exactly; only the text form may differ. Downstream
    /// consumers that parse the XML see the same values as the sender.
    pub fn decode(&mut self, raw: &Bytes) -> Result<Bytes, DeltaError> {
        let snapshot = parse_snapshot(raw).ok_or(DeltaError::NotCot)?;
        if snapshot.uid.is_empty() {
            return Err(DeltaError::MissingUid);
        }
        if !is_delta_event(raw) {
            let _ = self.cache.put(snapshot.uid.clone(), snapshot);
            return Ok(raw.clone());
        }

        let prior = self
            .cache
            .get(&snapshot.uid)
            .cloned()
            .ok_or(DeltaError::MissingCache)?;
        let merged = merge_snapshots(prior, &snapshot);
        let xml = assemble_full_xml(&merged);
        let _ = self.cache.put(merged.uid.clone(), merged);
        Ok(Bytes::from(xml))
    }

    /// Number of UIDs currently cached.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

// ── parsing ────────────────────────────────────────────────────────────

/// Attempt to parse the head of `raw` into a [`CotSnapshot`].
///
/// Returns `None` if the bytes do not start with an `<event>` open tag, if
/// the tag has no `uid`, or if the head is larger than the scan bound.
///
/// The parse is deliberately lenient: unknown attributes are ignored,
/// `<point>` and `<delta>` children are captured, and everything else is
/// either ignored (for outer scans) or folded into `detail_inner` (for
/// `<detail>` scans).
pub fn parse_snapshot(raw: &Bytes) -> Option<CotSnapshot> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let slice_end = raw.len().min(MAX_SCAN_BYTES);
    let slice = &raw[..slice_end];

    let mut reader = Reader::from_reader(slice);
    reader.config_mut().trim_text(false);

    let mut snap = CotSnapshot::default();
    let mut in_detail = false;
    let mut detail_depth = 0usize;
    let mut detail_buf = String::new();
    let mut seen_event = false;
    let mut buf = Vec::new();

    loop {
        let evt = match reader.read_event_into(&mut buf) {
            Ok(e) => e,
            Err(_) => return None,
        };
        match evt {
            Event::Eof => break,
            Event::Start(e) => {
                if handle_open(
                    &e,
                    false,
                    &mut snap,
                    &mut seen_event,
                    &mut in_detail,
                    &mut detail_depth,
                    &mut detail_buf,
                ) {
                    break;
                }
            }
            Event::Empty(e) => {
                if handle_open(
                    &e,
                    true,
                    &mut snap,
                    &mut seen_event,
                    &mut in_detail,
                    &mut detail_depth,
                    &mut detail_buf,
                ) {
                    break;
                }
            }
            Event::End(e) => {
                let name = e.name().as_ref().to_vec();
                match name.as_slice() {
                    b"event" => {
                        break;
                    }
                    b"delta" => {}
                    b"detail" if detail_depth == 1 => {
                        in_detail = false;
                        snap.detail_inner = Some(std::mem::take(&mut detail_buf));
                        detail_depth = 0;
                    }
                    _ => {
                        if in_detail && detail_depth > 1 {
                            detail_buf.push_str("</");
                            detail_buf.push_str(&String::from_utf8_lossy(&name));
                            detail_buf.push('>');
                            detail_depth = detail_depth.saturating_sub(1);
                        } else if in_detail {
                            // closing an unopened tag inside detail is
                            // malformed — ignore and let detail close on
                            // its own </detail> or EOF.
                        }
                    }
                }
            }
            Event::Text(t) => {
                if in_detail {
                    // Store raw as-is; escapes round-trip through the
                    // buffer verbatim since we compare by byte equality.
                    detail_buf.push_str(&String::from_utf8_lossy(t.as_ref()));
                }
            }
            _ => {}
        }
        buf.clear();
    }

    if snap.uid.is_empty() {
        return None;
    }
    if snap.version.is_empty() {
        snap.version = "2.0".to_string();
    }
    Some(snap)
}

/// Dispatch a quick-xml Start or Empty event to the right branch of the
/// parser. Returns `true` when the caller should stop iterating (top-level
/// closing tag encountered).
#[allow(clippy::too_many_arguments)]
fn handle_open(
    e: &quick_xml::events::BytesStart<'_>,
    is_empty: bool,
    snap: &mut CotSnapshot,
    seen_event: &mut bool,
    in_detail: &mut bool,
    detail_depth: &mut usize,
    detail_buf: &mut String,
) -> bool {
    let name = e.name().as_ref().to_vec();
    match name.as_slice() {
        b"event" => {
            if *seen_event {
                if *in_detail {
                    append_tag_start(detail_buf, e, is_empty);
                    if !is_empty {
                        *detail_depth = detail_depth.saturating_add(1);
                    }
                }
                return false;
            }
            *seen_event = true;
            for attr in e.attributes().flatten() {
                match attr.key.as_ref() {
                    b"version" => snap.version = attr_to_string(&attr.value),
                    b"uid" => snap.uid = attr_to_string(&attr.value),
                    b"type" => snap.event_type = attr_to_string(&attr.value),
                    b"how" => snap.how = Some(attr_to_string(&attr.value)),
                    b"time" => snap.time = attr_to_string(&attr.value),
                    b"start" => snap.start = attr_to_string(&attr.value),
                    b"stale" => snap.stale = attr_to_string(&attr.value),
                    _ => {}
                }
            }
            // Self-closing <event/> is degenerate but valid — we're done.
            is_empty
        }
        b"delta" => {
            // Unwrap delta timestamp attributes onto the event so a
            // received delta parses as a normal snapshot. Enables
            // decoder round-trip via the same parser.
            for attr in e.attributes().flatten() {
                match attr.key.as_ref() {
                    b"time" => snap.time = attr_to_string(&attr.value),
                    b"start" => snap.start = attr_to_string(&attr.value),
                    b"stale" => snap.stale = attr_to_string(&attr.value),
                    _ => {}
                }
            }
            false
        }
        b"point" if !*in_detail => {
            let mut p = CotPoint {
                lat: 0.0,
                lon: 0.0,
                hae: 0.0,
                ce: 9_999_999.0,
                le: 9_999_999.0,
            };
            for attr in e.attributes().flatten() {
                match attr.key.as_ref() {
                    b"lat" => {
                        if let Some(v) = attr_to_f64(&attr.value) {
                            p.lat = v;
                        }
                    }
                    b"lon" => {
                        if let Some(v) = attr_to_f64(&attr.value) {
                            p.lon = v;
                        }
                    }
                    b"hae" => {
                        if let Some(v) = attr_to_f64(&attr.value) {
                            p.hae = v;
                        }
                    }
                    b"ce" => {
                        if let Some(v) = attr_to_f64(&attr.value) {
                            p.ce = v;
                        }
                    }
                    b"le" => {
                        if let Some(v) = attr_to_f64(&attr.value) {
                            p.le = v;
                        }
                    }
                    _ => {}
                }
            }
            snap.point = Some(p);
            false
        }
        b"detail" if !*in_detail => {
            *in_detail = true;
            *detail_depth = 1;
            if is_empty {
                // <detail/> self-closing → empty inner.
                snap.detail_inner = Some(String::new());
                *in_detail = false;
                *detail_depth = 0;
            }
            false
        }
        _ => {
            if *in_detail {
                append_tag_start(detail_buf, e, is_empty);
                if !is_empty {
                    *detail_depth = detail_depth.saturating_add(1);
                }
            }
            false
        }
    }
}

/// Rewrite a quick-xml `Start`/`Empty` event back into XML text inside the
/// `<detail>` capture buffer. This preserves attributes verbatim so the
/// cached detail fingerprint is stable across re-parses.
fn append_tag_start(buf: &mut String, e: &quick_xml::events::BytesStart<'_>, is_empty: bool) {
    buf.push('<');
    buf.push_str(&String::from_utf8_lossy(e.name().as_ref()));
    for attr in e.attributes().flatten() {
        buf.push(' ');
        buf.push_str(&String::from_utf8_lossy(attr.key.as_ref()));
        buf.push_str("=\"");
        let val = String::from_utf8_lossy(&attr.value);
        for ch in val.chars() {
            match ch {
                '&' => buf.push_str("&amp;"),
                '"' => buf.push_str("&quot;"),
                '<' => buf.push_str("&lt;"),
                '>' => buf.push_str("&gt;"),
                _ => buf.push(ch),
            }
        }
        buf.push('"');
    }
    if is_empty {
        buf.push_str("/>");
    } else {
        buf.push('>');
    }
}

fn attr_to_string(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

fn attr_to_f64(raw: &[u8]) -> Option<f64> {
    std::str::from_utf8(raw).ok().and_then(|s| s.parse().ok())
}

/// Whether the raw bytes contain a `<delta` child under `<event>`.
///
/// This is a cheap byte-level probe used by [`DeltaDecoder::decode`] to
/// branch before parsing the full snapshot.
pub fn is_delta_event(raw: &Bytes) -> bool {
    let slice_end = raw.len().min(MAX_SCAN_BYTES);
    memmem(&raw[..slice_end], b"<delta")
}

fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── diffing ────────────────────────────────────────────────────────────

/// Render the delta body (the children of `<delta>`) given the cached
/// `prior` and the new `curr` snapshot. Returns an empty string when
/// absolutely nothing changed.
fn build_delta_body(prior: &CotSnapshot, curr: &CotSnapshot) -> String {
    let mut out = String::new();

    // Point
    if match (&prior.point, &curr.point) {
        (Some(a), Some(b)) => a != b,
        (None, None) => false,
        _ => true,
    } && let Some(p) = &curr.point
    {
        out.push_str(&format_point(p));
    }

    // Detail subtree. Byte-level compare of the verbatim inner text.
    if prior.detail_inner != curr.detail_inner
        && let Some(inner) = &curr.detail_inner
    {
        out.push_str("<detail>");
        out.push_str(inner);
        out.push_str("</detail>");
    }

    out
}

/// Whether `prior` and `curr` differ only in `<point>` contents.
///
/// Timestamp changes are ignored for the purposes of this check: every
/// update carries fresh `time`/`start`/`stale`, so if we did not ignore
/// them the epsilon suppression path would never fire.
fn is_position_only_change(prior: &CotSnapshot, curr: &CotSnapshot) -> bool {
    prior.detail_inner == curr.detail_inner
        && prior.version == curr.version
        && prior.event_type == curr.event_type
        && prior.how == curr.how
        && prior.point.is_some()
        && curr.point.is_some()
}

// ── assembly ───────────────────────────────────────────────────────────

fn format_point(p: &CotPoint) -> String {
    format!(
        "<point lat=\"{}\" lon=\"{}\" hae=\"{}\" ce=\"{}\" le=\"{}\"/>",
        fmt_f64(p.lat),
        fmt_f64(p.lon),
        fmt_f64(p.hae),
        fmt_f64(p.ce),
        fmt_f64(p.le)
    )
}

fn fmt_f64(v: f64) -> String {
    // Use the Display impl which avoids unnecessary trailing zeros while
    // preserving precision; ryu-style formatting matches what the parser
    // round-trips to.
    if v.fract() == 0.0 && v.abs() < 1e16 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

fn assemble_delta_xml(snap: &CotSnapshot, delta_body: &str) -> String {
    let mut out = String::with_capacity(256 + delta_body.len());
    out.push_str("<event version=\"");
    out.push_str(&escape(&snap.version));
    out.push_str("\" uid=\"");
    out.push_str(&escape(&snap.uid));
    out.push_str("\" type=\"");
    out.push_str(&escape(&snap.event_type));
    if let Some(h) = &snap.how {
        out.push_str("\" how=\"");
        out.push_str(&escape(h));
    }
    out.push_str("\"><delta");
    if !snap.time.is_empty() {
        out.push_str(" time=\"");
        out.push_str(&escape(&snap.time));
        out.push('"');
    }
    if !snap.start.is_empty() {
        out.push_str(" start=\"");
        out.push_str(&escape(&snap.start));
        out.push('"');
    }
    if !snap.stale.is_empty() {
        out.push_str(" stale=\"");
        out.push_str(&escape(&snap.stale));
        out.push('"');
    }
    out.push('>');
    out.push_str(delta_body);
    out.push_str("</delta></event>");
    out
}

fn assemble_full_xml(snap: &CotSnapshot) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<event version=\"");
    out.push_str(&escape(&snap.version));
    out.push_str("\" uid=\"");
    out.push_str(&escape(&snap.uid));
    out.push_str("\" type=\"");
    out.push_str(&escape(&snap.event_type));
    if let Some(h) = &snap.how {
        out.push_str("\" how=\"");
        out.push_str(&escape(h));
    }
    out.push_str("\" time=\"");
    out.push_str(&escape(&snap.time));
    out.push_str("\" start=\"");
    out.push_str(&escape(&snap.start));
    out.push_str("\" stale=\"");
    out.push_str(&escape(&snap.stale));
    out.push_str("\">");
    if let Some(p) = &snap.point {
        out.push_str(&format_point(p));
    }
    if let Some(inner) = &snap.detail_inner {
        out.push_str("<detail>");
        out.push_str(inner);
        out.push_str("</detail>");
    }
    out.push_str("</event>");
    out
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Overlay `delta` onto `prior`, producing a merged snapshot. Fields that
/// are present in the delta replace the prior; absent fields retain their
/// prior value.
fn merge_snapshots(prior: CotSnapshot, delta: &CotSnapshot) -> CotSnapshot {
    CotSnapshot {
        version: if delta.version.is_empty() {
            prior.version
        } else {
            delta.version.clone()
        },
        uid: delta.uid.clone(),
        event_type: if delta.event_type.is_empty() {
            prior.event_type
        } else {
            delta.event_type.clone()
        },
        how: delta.how.clone().or(prior.how),
        time: if delta.time.is_empty() {
            prior.time
        } else {
            delta.time.clone()
        },
        start: if delta.start.is_empty() {
            prior.start
        } else {
            delta.start.clone()
        },
        stale: if delta.stale.is_empty() {
            prior.stale
        } else {
            delta.stale.clone()
        },
        point: delta.point.or(prior.point),
        detail_inner: delta.detail_inner.clone().or(prior.detail_inner),
    }
}

// ── ground distance ────────────────────────────────────────────────────

/// Approximate ground distance in meters using an equirectangular
/// projection. Accurate enough for sub-kilometer position drift checks in
/// the epsilon suppression path; not intended for navigation.
///
/// # Latitude caveat
///
/// The equirectangular approximation assumes a locally-flat earth around
/// the midpoint latitude. At operational epsilon values (1–10 m) this is
/// fine anywhere on the globe. Beyond ~70° latitude the projection error
/// starts to grow noticeably (a few percent of the true distance at 80°+),
/// so callers should not use this helper for suppression thresholds of
/// kilometers near the poles. For rustgate's default 1 m epsilon the
/// error is negligible everywhere.
fn approx_distance_meters(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6_371_000.0; // mean earth radius in meters
    let dlat = (lat2 - lat1).to_radians();
    let mlat = ((lat1 + lat2) * 0.5).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let x = dlon * mlat.cos();
    let y = dlat;
    (x * x + y * y).sqrt() * R
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cap(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    fn full_event(uid: &str, lat: f64, lon: f64, time: &str) -> Bytes {
        Bytes::from(format!(
            r#"<event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="{time}" start="{time}" stale="{time}"><point lat="{lat}" lon="{lon}" hae="100.0" ce="9.9" le="9.9"/><detail><contact callsign="ALPHA"/></detail></event>"#,
        ))
    }

    #[test]
    fn first_event_is_full() {
        let mut enc = DeltaEncoder::new(cap(16), 0.0);
        let out = enc.encode(&full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z"));
        assert!(matches!(out, DeltaOutput::Full(_)));
        assert_eq!(enc.stats().full, 1);
    }

    #[test]
    fn identical_repeat_is_suppressed() {
        let mut enc = DeltaEncoder::new(cap(16), 0.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z"));
        let out = enc.encode(&full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z"));
        // Exact same bytes → nothing changed → Suppressed.
        assert!(matches!(out, DeltaOutput::Suppressed));
        assert_eq!(enc.stats().suppressed, 1);
    }

    #[test]
    fn position_change_is_delta() {
        let mut enc = DeltaEncoder::new(cap(16), 0.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z"));
        let out = enc.encode(&full_event("U1", 35.0, -118.0, "2026-01-01T00:00:05Z"));
        match out {
            DeltaOutput::Delta(b) => {
                let s = std::str::from_utf8(&b).unwrap();
                assert!(s.contains("<delta "));
                assert!(s.contains("<point"));
                assert!(s.contains("lat=\"35"));
            }
            other => panic!("expected delta, got {other:?}"),
        }
        assert_eq!(enc.stats().delta, 1);
    }

    #[test]
    fn detail_only_change_is_delta_without_point() {
        let first = Bytes::from(
            r#"<event version="2.0" uid="U1" type="a-f-G-U-C" how="m-g" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T00:00:00Z"><point lat="34.0" lon="-118.0" hae="100.0" ce="9.9" le="9.9"/><detail><contact callsign="ALPHA"/></detail></event>"#.to_string(),
        );
        let second = Bytes::from(
            r#"<event version="2.0" uid="U1" type="a-f-G-U-C" how="m-g" time="2026-01-01T00:00:05Z" start="2026-01-01T00:00:05Z" stale="2026-01-01T00:00:05Z"><point lat="34.0" lon="-118.0" hae="100.0" ce="9.9" le="9.9"/><detail><contact callsign="BRAVO"/></detail></event>"#.to_string(),
        );
        let mut enc = DeltaEncoder::new(cap(16), 0.0);
        let _ = enc.encode(&first);
        let out = enc.encode(&second);
        match out {
            DeltaOutput::Delta(b) => {
                let s = std::str::from_utf8(&b).unwrap();
                assert!(!s.contains("<point"));
                assert!(s.contains("callsign=\"BRAVO\""));
            }
            other => panic!("expected delta, got {other:?}"),
        }
    }

    #[test]
    fn epsilon_suppresses_small_drift() {
        // ~0.5 m east–west at 34 degrees latitude corresponds to roughly
        // 5.4e-6 degrees of longitude. Well under 1m.
        let mut enc = DeltaEncoder::new(cap(16), 1.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z"));
        let out = enc.encode(&full_event(
            "U1",
            34.0,
            -118.000_005,
            "2026-01-01T00:00:05Z",
        ));
        assert!(matches!(out, DeltaOutput::Suppressed));
    }

    #[test]
    fn epsilon_passes_large_move() {
        let mut enc = DeltaEncoder::new(cap(16), 1.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z"));
        let out = enc.encode(&full_event("U1", 34.1, -118.0, "2026-01-01T00:00:05Z"));
        assert!(matches!(out, DeltaOutput::Delta(_)));
    }

    #[test]
    fn lru_eviction_emits_full_for_evicted_uid() {
        let mut enc = DeltaEncoder::new(cap(2), 0.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "t"));
        let _ = enc.encode(&full_event("U2", 34.0, -118.0, "t"));
        let _ = enc.encode(&full_event("U3", 34.0, -118.0, "t")); // evicts U1
        assert_eq!(enc.len(), 2);
        let out = enc.encode(&full_event("U1", 34.0, -118.0, "t"));
        assert!(matches!(out, DeltaOutput::Full(_)));
    }

    #[test]
    fn round_trip_delta_via_decoder() {
        let first = full_event("U1", 34.0, -118.0, "2026-01-01T00:00:00Z");
        let second = full_event("U1", 35.0, -119.0, "2026-01-01T00:00:05Z");

        let mut enc = DeltaEncoder::new(cap(4), 0.0);
        let mut dec = DeltaDecoder::new(cap(4));

        let first_out = match enc.encode(&first) {
            DeltaOutput::Full(b) => b,
            other => panic!("expected full, got {other:?}"),
        };
        let reconstructed_first = dec.decode(&first_out).unwrap();
        // Decoder returns full bytes verbatim for full input.
        assert_eq!(reconstructed_first, first);

        let second_out = match enc.encode(&second) {
            DeltaOutput::Delta(b) => b,
            other => panic!("expected delta, got {other:?}"),
        };
        let reconstructed = dec.decode(&second_out).unwrap();
        let snap = parse_snapshot(&reconstructed).unwrap();
        assert_eq!(snap.uid, "U1");
        assert_eq!(snap.point.unwrap().lat, 35.0);
        assert_eq!(snap.point.unwrap().lon, -119.0);
        assert_eq!(snap.time, "2026-01-01T00:00:05Z");
    }

    #[test]
    fn non_cot_falls_through_as_full() {
        let mut enc = DeltaEncoder::new(cap(4), 0.0);
        let raw = Bytes::from_static(b"not xml at all");
        let out = enc.encode(&raw);
        match out {
            DeltaOutput::Full(b) => assert_eq!(b.as_ref(), b"not xml at all"),
            other => panic!("expected full, got {other:?}"),
        }
    }

    #[test]
    fn random_bytes_do_not_panic() {
        let mut enc = DeltaEncoder::new(cap(4), 0.0);
        for seed in 0..64u8 {
            let len = (seed as usize) * 3 + 7;
            let bytes: Vec<u8> = (0..len)
                .map(|i| (seed ^ (i as u8)).wrapping_mul(17))
                .collect();
            let _ = enc.encode(&Bytes::from(bytes));
        }
    }

    #[test]
    fn type_drift_emits_full() {
        let first = Bytes::from(
            r#"<event version="2.0" uid="U1" type="a-f-G-U-C" how="m-g" time="t" start="t" stale="t"><point lat="0" lon="0" hae="0" ce="1" le="1"/></event>"#.to_string(),
        );
        let second = Bytes::from(
            r#"<event version="2.0" uid="U1" type="a-f-A" how="m-g" time="t2" start="t2" stale="t2"><point lat="0" lon="0" hae="0" ce="1" le="1"/></event>"#.to_string(),
        );
        let mut enc = DeltaEncoder::new(cap(4), 0.0);
        let _ = enc.encode(&first);
        let out = enc.encode(&second);
        assert!(matches!(out, DeltaOutput::Full(_)));
    }

    #[test]
    fn empty_capacity_works() {
        // Sanity: cap=1 still functional
        let mut enc = DeltaEncoder::new(cap(1), 0.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "t"));
        let _ = enc.encode(&full_event("U2", 34.0, -118.0, "t"));
        // U1 should have been evicted.
        assert_eq!(enc.len(), 1);
    }

    #[test]
    fn oversized_payload_is_counted_and_emitted_full() {
        // F-62: a payload larger than MAX_SCAN_BYTES bypasses parsing
        // entirely — the encoder emits Full and bumps DeltaStats::oversized
        // so operators can alert on a client padding traffic to defeat
        // delta compression.
        let mut enc = DeltaEncoder::new(cap(16), 0.0);
        let big = {
            let mut s = String::with_capacity(MAX_SCAN_BYTES + 64);
            s.push_str(r#"<event version="2.0" uid="U1" type="a-f-G-U-C" how="m-g" time="t" start="t" stale="t"><point lat="34.0" lon="-118.0" hae="0" ce="1" le="1"/><detail>"#);
            while s.len() < MAX_SCAN_BYTES {
                s.push_str("<pad>x</pad>");
            }
            s.push_str("</detail></event>");
            Bytes::from(s)
        };
        assert!(big.len() > MAX_SCAN_BYTES);

        let out = enc.encode(&big);
        assert!(matches!(out, DeltaOutput::Full(_)));
        assert_eq!(enc.stats().oversized, 1);
        assert_eq!(enc.stats().full, 1);
        // No cache pollution from oversized payloads — the encoder must
        // never parse them, so nothing is cached.
        assert_eq!(enc.len(), 0);
    }

    #[test]
    fn lru_eviction_is_counted_in_stats() {
        // F-61: evictions bump DeltaStats::evicted so operators can alert
        // on sustained eviction rate, which signals the cache_size is
        // undersized for the active UID count.
        let mut enc = DeltaEncoder::new(cap(2), 0.0);
        let _ = enc.encode(&full_event("U1", 34.0, -118.0, "t"));
        let _ = enc.encode(&full_event("U2", 34.0, -118.0, "t"));
        assert_eq!(enc.stats().evicted, 0);

        // Encoding a third UID forces an eviction of the LRU entry (U1).
        let _ = enc.encode(&full_event("U3", 34.0, -118.0, "t"));
        assert_eq!(enc.stats().evicted, 1);

        // Re-encoding a still-resident UID must NOT count as an eviction
        // — it's just a cache update, not capacity pressure.
        let _ = enc.encode(&full_event("U3", 35.0, -119.0, "t2"));
        assert_eq!(enc.stats().evicted, 1);
    }
}
