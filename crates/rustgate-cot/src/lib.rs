// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Cursor on Target (CoT) XML parsing and message building.
//!
//! # Security
//!
//! This parser uses `quick-xml`, a streaming parser that does not resolve
//! external entities or process DTD declarations. This design prevents
//! XXE (XML External Entity) injection attacks by default.
//!
//! # Error handling
//!
//! Top-level CoT parsing returns this crate's [`ParseError`]; the
//! masking and delta-compression submodules expose their own typed
//! enums ([`mask::MaskError`], [`delta::DeltaError`]). Binary callers
//! propagate these via `?` and map them through `anyhow::Error` at the
//! orchestration layer; [`rustgate_core::error::RustgateError`] is the
//! boundary aggregator for the `rustgate-core` / `rustgate-transport`
//! slice and is not automatically constructed from this crate's
//! per-submodule errors.

pub mod cdi;
pub mod delta;
pub mod entity;
pub mod mask;
#[cfg(feature = "metrics")]
pub mod metrics;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use bytes::Bytes;
use quick_xml::Reader;
use quick_xml::events::Event;
use rustgate_core::identity::Identity;
use rustgate_core::message::{Destination, MessageType, Metadata, RoutableMessage};

/// A parsed Cursor-on-Target event with metadata, position, and destination.
#[derive(Debug, Clone)]
pub struct CotEvent {
    pub uid: String,
    pub event_type: String,
    pub destination: CotDestination,
    pub message_type: MessageType,
    pub position: Option<Position>,
    pub ttl: Option<Duration>,
    /// Source group from `<__group name="..."/>` detail element (e.g., "Cyan").
    pub source_group: Option<String>,
}

/// Routing destination for a CoT event: broadcast, group, or direct.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub enum CotDestination {
    Broadcast,
    Callsign(String),
    Group(String),
}

/// Geographic position with latitude, longitude, and altitude.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct Position {
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
    /// Circular error (metres) from the `<point ce>` attribute, if present
    /// and numeric. Senders mark an unknown position with a very large
    /// value (`9999999` by TAK convention).
    pub ce: Option<f64>,
    /// Linear (vertical) error (metres) from `<point le>`, if present and
    /// numeric.
    pub le: Option<f64>,
}

/// Parse a `ce`/`le` attribute. Non-numeric and non-finite values (`NaN`,
/// `inf`) yield `None`: downstream JSON encoders cannot represent them.
fn parse_accuracy(value: &str) -> Option<f64> {
    value.trim().parse::<f64>().ok().filter(|v| v.is_finite())
}

/// Errors that can occur when parsing CoT XML.
///
/// Closes #847 — the `Display` and `std::error::Error` impls below
/// satisfy the
/// [`rustgate_core::entity::DynEntityCodec`] blanket impl bound so the
/// router-side [`rustgate_core::entity::EntityCodecRegistry`] can hold
/// a [`crate::entity::CotEntityCodec`] under the heterogeneous codec
/// type. The thiserror macro generates a `Display` whose output mirrors
/// the variant payloads — operators relying on the `{}` format of a
/// `ParseError` see the same human-readable shape they would have
/// gotten from `Debug` formatting before.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("XML parse error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("missing required attribute: {0}")]
    MissingAttribute(&'static str),
    #[error("invalid float for field: {0}")]
    InvalidFloat(&'static str),
    /// A numeric field was out of its spec-defined range.
    ///
    /// MITRE CoT Message Router User's Guide (MP090284) Table 2-1 defines
    /// `lat` and `lon` in WGS-84 decimal degrees: latitude -90..=90,
    /// longitude -180..=180. Values outside these ranges are rejected
    /// rather than propagated to downstream geofilter / multicast logic.
    #[error("field `{field}` out of range: {value}")]
    OutOfRange { field: &'static str, value: f64 },
    /// The `<detail>` subtree nested deeper than `MAX_DETAIL_DEPTH`.
    ///
    /// Mirrors the `MAX_XML_DEPTH` cap the transport and TLS XML surfaces
    /// enforce, so a pathologically nested payload cannot inflate the
    /// attribute-key strings without bound.
    #[error("detail nesting exceeds {max} levels")]
    DetailTooDeep { max: usize },
    /// The flattened `<detail>` attribute bag exceeded
    /// `MAX_ATTR_BAG_BYTES`.
    ///
    /// Mirrors the `MAX_ATTR_BAG_BYTES` cap enforced on the SAN /
    /// certificate attribute surfaces, so a payload with thousands of
    /// tiny detail elements cannot balloon the per-entity attribute map.
    #[error("detail attribute bag exceeds {max} bytes")]
    AttrBagTooLarge { max: usize },
}

#[cfg(feature = "fuzz")]
impl<'a> Arbitrary<'a> for CotEvent {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let uid_len = u.int_in_range(1..=32)?;
        let uid: String = (0..uid_len)
            .map(|_| u.int_in_range(b'a'..=b'z').map(|b| b as char))
            .collect::<arbitrary::Result<_>>()?;

        // Generate realistic CoT event types
        let event_types = ["a-f-G-U-C", "a-h-G", "b-t-f", "b-a-o-tbl", "t-x-c-t"];
        let idx = u.int_in_range(0..=4)?;
        let event_type = event_types[idx].to_string();

        let ttl_secs: Option<u64> = u.arbitrary()?;
        let ttl = ttl_secs.map(|s| Duration::from_secs(s % 86400));

        Ok(Self {
            uid,
            event_type,
            destination: u.arbitrary()?,
            message_type: u.arbitrary()?,
            position: u.arbitrary()?,
            ttl,
            source_group: u.arbitrary()?,
        })
    }
}

/// CoT Situational Awareness affiliation derived from the event type hierarchy.
///
/// The affiliation is encoded as the second segment of an "atom" event type
/// string (e.g., `a-f-G-U-C` → `Friend`). The 11 codes below are the full set
/// defined by MITRE CoT Message Router User's Guide (MP090284) Appendix A
/// "Is Predicate Tests" and Figure 2-3, aligned with MIL-STD-2525 standard
/// identity codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaAffiliation {
    /// Pending (`a-p-*`).
    Pending,
    /// Assumed friend (`a-a-*`).
    AssumedFriend,
    /// Friend (`a-f-*`).
    Friend,
    /// Neutral (`a-n-*`).
    Neutral,
    /// Suspect (`a-s-*`).
    Suspect,
    /// Hostile (`a-h-*`).
    Hostile,
    /// Joker (`a-j-*`).
    Joker,
    /// Faker (`a-k-*`).
    Faker,
    /// Unknown (`a-u-*`).
    Unknown,
    /// None specified (`a-o-*`).
    NoneSpecified,
    /// Other (`a-x-*`).
    Other,
}

/// Returns `true` if the CoT event type represents a Situational Awareness atom.
///
/// SA atoms take the form `a-X-…` where `X` is one of the 11 Appendix A
/// affiliation codes (`p/a/f/n/s/h/j/k/u/o/x`).
pub fn is_sa_event(event_type: &str) -> bool {
    sa_affiliation(event_type).is_some()
}

/// Extracts the SA affiliation from a CoT event type, if it is an SA atom.
///
/// Returns `None` for non-SA event types (e.g., `"b-t-f"`, `"t-x-d"`) or
/// for atoms with an unrecognized affiliation character.
pub fn sa_affiliation(event_type: &str) -> Option<SaAffiliation> {
    // SA atoms have the form "a-X-..." where X is the affiliation character.
    let bytes = event_type.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'a' || bytes[1] != b'-' || bytes[3] != b'-' {
        return None;
    }
    match bytes[2] {
        b'p' => Some(SaAffiliation::Pending),
        b'a' => Some(SaAffiliation::AssumedFriend),
        b'f' => Some(SaAffiliation::Friend),
        b'n' => Some(SaAffiliation::Neutral),
        b's' => Some(SaAffiliation::Suspect),
        b'h' => Some(SaAffiliation::Hostile),
        b'j' => Some(SaAffiliation::Joker),
        b'k' => Some(SaAffiliation::Faker),
        b'u' => Some(SaAffiliation::Unknown),
        b'o' => Some(SaAffiliation::NoneSpecified),
        b'x' => Some(SaAffiliation::Other),
        _ => None,
    }
}

rustgate_core::on_callback!(
    /// Callback invoked once per CoT payload whose `<event version=…>`
    /// attribute was rewritten by [`auto_upgrade_sa_version`] from a legacy
    /// value to the current `2.0` form.
    ///
    /// The single `&str` argument is the `from_version` label — one of the
    /// values returned by [`classify_legacy_sa_version`]
    /// (`"v1"`, `"v2-pre-2.0"`). The server binary wires this callback to
    /// the `rustgate_sa_auto_upgraded_total{from_version}` Prometheus
    /// counter so fleet-upgrade-progress dashboards can plot the share of
    /// senders still emitting legacy formats. Closes #741.
    ///
    /// Kept as a simple `Fn(&str)` so the `rustgate-cot` crate stays
    /// metrics-agnostic and does not grow a `prometheus` dependency.
    pub OnSaAutoUpgraded,
    &str
);

/// Current CoT event-schema version produced by the auto-upgrade path.
///
/// Used as the rewrite target by [`auto_upgrade_sa_version`]. Pinned to
/// `"2.0"` because that is the canonical MITRE MP090284 envelope —
/// the auto-upgrade flow lifts pre-2.0 payloads to this version so the
/// rest of the routing pipeline only ever sees the modern form.
pub const CURRENT_SA_VERSION: &str = "2.0";

/// Classifies a CoT XML payload's `<event version=…>` attribute as a
/// legacy form, returning the `from_version` label that
/// [`auto_upgrade_sa_version`] will fire on its callback. Returns
/// `None` for current-version (`"2.0"` or newer) payloads and for
/// non-CoT bytes.
///
/// The classification is intentionally byte-level: scanning the first
/// 4 KiB of the payload is dramatically cheaper than full XML
/// re-parsing on every message, and the existing `parse()` path drops
/// the version attribute entirely so a downstream call cannot recover
/// it. The label values are stable across releases — operator
/// dashboards key off them.
///
/// **Returned labels (matches the
/// `rustgate_sa_auto_upgraded_total{from_version}` cardinality):**
/// - `"v1"` — payload is XML but the `<event>` tag is missing a
///   `version` attribute entirely. Common for very old TAK clients
///   (pre-version-attribute era) and some MAVLink-bridged emitters
///   that fabricate a minimal `<event>` shell.
/// - `"v2-pre-2.0"` — payload carries a `version="…"` attribute whose
///   value is below `"2.0"` (e.g. `"1.0"`, `"1.5"`, `"1.9"`). Treated
///   as a single bucket because most pre-2.0 versions in the wild are
///   `"1.0"` and finer cardinality would explode dashboards without
///   adding operational signal.
pub fn classify_legacy_sa_version(payload: &[u8]) -> Option<&'static str> {
    let event_attrs = find_event_attrs(payload)?;
    match find_version_attr(event_attrs) {
        None => Some("v1"),
        Some(v) if is_pre_2_0(v) => Some("v2-pre-2.0"),
        Some(_) => None,
    }
}

/// Rewrites the `<event version=…>` attribute on a CoT payload to the
/// current value when it carries a legacy form, invoking `on_upgrade`
/// with the `from_version` label so the caller can update its
/// metric/audit surface. Returns the (possibly rewritten) payload.
///
/// The rewrite is byte-level — the function does NOT round-trip the
/// XML through a parser. Re-parsing on every position update was
/// rejected because the SA pipeline already runs `parse()` once
/// downstream and a second pass would double the per-message CPU on
/// the routing hot path. A targeted byte-level edit also preserves
/// the original whitespace, attribute order, and namespace prefixes,
/// which avoids gratuitous churn for downstream dedup/cache layers
/// that key on byte identity.
///
/// `on_upgrade` is invoked exactly once per upgraded payload, before
/// the rewritten bytes are returned. It is **not** invoked when the
/// payload is already current. Closes #741.
pub fn auto_upgrade_sa_version<F: Fn(&str)>(payload: Bytes, on_upgrade: F) -> Bytes {
    let Some(label) = classify_legacy_sa_version(&payload) else {
        return payload;
    };
    on_upgrade(label);
    rewrite_event_version(&payload, CURRENT_SA_VERSION)
        .map(Bytes::from)
        .unwrap_or(payload)
}

/// Find the byte slice spanning the `<event …>` tag attributes — i.e.
/// the bytes between `<event` and the first `>` or `/>`.
///
/// Returns `None` if the payload does not start with the `<event` open
/// tag (after optional XML declaration / whitespace). The scan is
/// bounded to the first 4 KiB so an attacker cannot make the classifier
/// walk an arbitrarily large payload looking for the tag.
fn find_event_attrs(payload: &[u8]) -> Option<&[u8]> {
    const SCAN_BUDGET: usize = 4 * 1024;
    let scan = &payload[..payload.len().min(SCAN_BUDGET)];
    let start = find_subslice(scan, b"<event")?;
    let after_tag_name = start + b"<event".len();
    // The byte immediately after `<event` must be whitespace, `>`, or
    // `/` (for self-closing) — otherwise this is a different tag like
    // `<eventLog>`.
    let next = scan.get(after_tag_name).copied()?;
    if !matches!(next, b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/') {
        return None;
    }
    let end = scan[after_tag_name..]
        .iter()
        .position(|&b| b == b'>')
        .map(|p| after_tag_name + p)?;
    Some(&scan[after_tag_name..end])
}

/// Locate `version="…"` (or `version='…'`) inside a slice of `<event>`
/// attributes. Returns the value substring on hit.
fn find_version_attr(attrs: &[u8]) -> Option<&[u8]> {
    let key = b"version";
    let mut i = 0;
    while i + key.len() < attrs.len() {
        if &attrs[i..i + key.len()] == key {
            // Confirm word boundary on the left.
            let left_ok = i == 0 || matches!(attrs[i - 1], b' ' | b'\t' | b'\n' | b'\r');
            if left_ok {
                let after = i + key.len();
                // Skip optional whitespace then expect '='.
                let mut j = after;
                while j < attrs.len() && matches!(attrs[j], b' ' | b'\t') {
                    j += 1;
                }
                if attrs.get(j) == Some(&b'=') {
                    j += 1;
                    while j < attrs.len() && matches!(attrs[j], b' ' | b'\t') {
                        j += 1;
                    }
                    let quote = attrs.get(j).copied()?;
                    if quote != b'"' && quote != b'\'' {
                        return None;
                    }
                    j += 1;
                    let end_off = attrs[j..].iter().position(|&b| b == quote)?;
                    return Some(&attrs[j..j + end_off]);
                }
            }
        }
        i += 1;
    }
    None
}

/// Returns `true` when `value` parses as a CoT version strictly below
/// `2.0`. Unparseable values are treated as **not** pre-2.0 — the
/// payload is left alone rather than being rewritten on best-guess
/// data.
fn is_pre_2_0(value: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(value) else {
        return false;
    };
    let trimmed = s.trim();
    let mut parts = trimmed.splitn(2, '.');
    let Some(major_str) = parts.next() else {
        return false;
    };
    let Ok(major) = major_str.parse::<u32>() else {
        return false;
    };
    major < 2
}

/// Rewrite the `<event version=…>` attribute (or insert one if absent)
/// to `target`. Returns the new bytes, or `None` if the payload does
/// not contain a recognizable `<event>` tag.
fn rewrite_event_version(payload: &[u8], target: &str) -> Option<Vec<u8>> {
    const SCAN_BUDGET: usize = 4 * 1024;
    let scan_end = payload.len().min(SCAN_BUDGET);
    let tag_start = find_subslice(&payload[..scan_end], b"<event")?;
    let after_tag_name = tag_start + b"<event".len();
    let next = payload.get(after_tag_name).copied()?;
    if !matches!(next, b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/') {
        return None;
    }
    let attrs_end = payload[after_tag_name..scan_end]
        .iter()
        .position(|&b| b == b'>')
        .map(|p| after_tag_name + p)?;
    let attrs_slice = &payload[after_tag_name..attrs_end];

    // Locate an existing `version="…"` to splice over.
    let mut out = Vec::with_capacity(payload.len() + target.len() + 16);
    if let Some((rel_value_start, rel_value_end)) = find_version_value_span(attrs_slice) {
        let abs_start = after_tag_name + rel_value_start;
        let abs_end = after_tag_name + rel_value_end;
        out.extend_from_slice(&payload[..abs_start]);
        out.extend_from_slice(target.as_bytes());
        out.extend_from_slice(&payload[abs_end..]);
    } else {
        // No version attribute — insert one immediately after `<event`.
        out.extend_from_slice(&payload[..after_tag_name]);
        out.push(b' ');
        out.extend_from_slice(b"version=\"");
        out.extend_from_slice(target.as_bytes());
        out.push(b'"');
        out.extend_from_slice(&payload[after_tag_name..]);
    }
    Some(out)
}

/// Returns `(value_start, value_end)` byte offsets inside an attribute
/// slice for an existing `version="…"` (or `version='…'`) attribute.
fn find_version_value_span(attrs: &[u8]) -> Option<(usize, usize)> {
    let key = b"version";
    let mut i = 0;
    while i + key.len() < attrs.len() {
        if &attrs[i..i + key.len()] == key {
            let left_ok = i == 0 || matches!(attrs[i - 1], b' ' | b'\t' | b'\n' | b'\r');
            if left_ok {
                let after = i + key.len();
                let mut j = after;
                while j < attrs.len() && matches!(attrs[j], b' ' | b'\t') {
                    j += 1;
                }
                if attrs.get(j) == Some(&b'=') {
                    j += 1;
                    while j < attrs.len() && matches!(attrs[j], b' ' | b'\t') {
                        j += 1;
                    }
                    let quote = attrs.get(j).copied()?;
                    if quote != b'"' && quote != b'\'' {
                        return None;
                    }
                    j += 1;
                    let value_start = j;
                    let end_off = attrs[j..].iter().position(|&b| b == quote)?;
                    return Some((value_start, value_start + end_off));
                }
            }
        }
        i += 1;
    }
    None
}

/// Naive substring search bounded by `haystack.len()` — used only on
/// payload prefixes capped at 4 KiB so the linear scan is cheap.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Origin category of a CoT `<event how>` attribute per MP090284.
///
/// The first segment of the `how` string distinguishes the origin:
/// `m-*` for machine-generated data (GPS, radar, IR, fused sensors) and
/// `h-*` for human-supplied data (estimated, transcribed, manually plotted).
/// Anything else is [`HowOrigin::Other`] — the TAK ecosystem is loose here
/// and field devices emit vendor-specific values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HowOrigin {
    /// Machine-generated (`m-*`).
    Machine,
    /// Human-supplied (`h-*`).
    Human,
    /// Neither prefix — non-conforming to the MP090284 taxonomy.
    Other,
}

/// Canonical `how` values defined by MITRE MP090284 Appendix C.
///
/// This is the strict set used by [`how_is_spec_conformant`]. Keep sorted
/// by origin (machine then human) and by sub-segment for readability.
const SPEC_HOW_VALUES: &[&str] = &[
    // Machine origin
    "m-g",   // GPS
    "m-g-a", // GPS with attitude (heading/pitch/roll)
    "m-g-n", // GPS, no altitude
    "m-f",   // fused sensor
    "m-n",   // inertial navigation
    "m-r",   // radar
    "m-i",   // infrared
    // Human origin
    "h-e",       // estimated
    "h-g-i-g-o", // geocoded, other
    "h-t",       // transcribed
    "h-s",       // sensor (human-operated)
    "h-p",       // portrayed (manual plot)
    "h-c",       // calculated
];

/// Classifies a CoT `<event how>` attribute by origin.
///
/// Inspects only the first segment — `m-*` returns [`HowOrigin::Machine`],
/// `h-*` returns [`HowOrigin::Human`], everything else returns
/// [`HowOrigin::Other`]. Use [`how_is_spec_conformant`] for strict
/// conformance against the MP090284 value list.
///
/// This is an opt-in classifier for observability (metrics, filtering,
/// dashboards). It does not validate the full value and never rejects
/// input — field devices emit non-canonical `how` strings and rustgate
/// forwards them unchanged to preserve interop.
pub fn how_origin(how: &str) -> HowOrigin {
    let bytes = how.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b'-' {
        match bytes[0] {
            b'm' => return HowOrigin::Machine,
            b'h' => return HowOrigin::Human,
            _ => {}
        }
    }
    HowOrigin::Other
}

/// Returns `true` if `how` matches one of the values defined by MP090284.
///
/// The check is exact and case-sensitive. Callers that want to emit a
/// metric or structured warning when encountering non-canonical `how`
/// values (common in practice) can guard on this helper. It is not used
/// to reject traffic — see [`how_origin`] for the rationale.
pub fn how_is_spec_conformant(how: &str) -> bool {
    SPEC_HOW_VALUES.contains(&how)
}

/// Parses a CoT XML byte slice into a [`CotEvent`].
///
/// Under the `metrics` feature, every call increments
/// `rustgate_cot_parse_total{result}` (`ok` | `err`) and observes its
/// wall-clock duration into `rustgate_cot_parse_seconds`. The metrics
/// wrap is feature-gated so the no-features build emits no extra
/// instructions on the parse hot path.
pub fn parse(xml: &[u8]) -> Result<CotEvent, ParseError> {
    #[cfg(feature = "metrics")]
    let _start = std::time::Instant::now();
    let result = parse_inner(xml);
    #[cfg(feature = "metrics")]
    {
        let elapsed = _start.elapsed().as_secs_f64();
        metrics::parse_seconds().observe(elapsed);
        let label = if result.is_ok() { "ok" } else { "err" };
        metrics::parse_total().with_label_values(&[label]).inc();
    }
    result
}

fn parse_inner(xml: &[u8]) -> Result<CotEvent, ParseError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut uid = None;
    let mut event_type = None;
    let mut position = None;
    let mut dest_callsign = None;
    let mut dest_group = None;
    let mut source_group = None;
    let mut stale_time = None;
    let mut start_time = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => match e.name().as_ref() {
                "event" => {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            "uid" => uid = Some(attr.value.to_string()),
                            "type" => event_type = Some(attr.value.to_string()),
                            "stale" => stale_time = Some(attr.value.to_string()),
                            "start" => start_time = Some(attr.value.to_string()),
                            _ => {}
                        }
                    }
                }
                "point" => {
                    let mut lat = None;
                    let mut lon = None;
                    let mut hae = None;
                    let mut ce = None;
                    let mut le = None;
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            "lat" => {
                                let v = parse_f64(&attr.value, "lat")?;
                                check_range("lat", v, -90.0, 90.0)?;
                                lat = Some(v);
                            }
                            "lon" => {
                                let v = parse_f64(&attr.value, "lon")?;
                                check_range("lon", v, -180.0, 180.0)?;
                                lon = Some(v);
                            }
                            "hae" => hae = Some(parse_f64(&attr.value, "hae")?),
                            // ce/le are optional accuracy hints: a missing or
                            // malformed value is ignored rather than rejecting
                            // the event, as before they were parsed at all.
                            "ce" => ce = parse_accuracy(&attr.value),
                            "le" => le = parse_accuracy(&attr.value),
                            _ => {}
                        }
                    }
                    if let (Some(lat), Some(lon), Some(hae)) = (lat, lon, hae) {
                        position = Some(Position {
                            lat,
                            lon,
                            hae,
                            ce,
                            le,
                        });
                    }
                }
                "dest" => {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            "callsign" => dest_callsign = Some(attr.value.to_string()),
                            "group" => dest_group = Some(attr.value.to_string()),
                            _ => {}
                        }
                    }
                }
                "__group" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == "name" {
                            source_group = Some(attr.value.to_string());
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }

    let uid = uid.ok_or(ParseError::MissingAttribute("uid"))?;
    let event_type = event_type.ok_or(ParseError::MissingAttribute("type"))?;

    let destination = match (dest_callsign, dest_group) {
        (Some(callsign), _) => CotDestination::Callsign(callsign),
        (None, Some(group)) => CotDestination::Group(group),
        (None, None) => CotDestination::Broadcast,
    };

    let message_type = map_event_type(&event_type);
    let ttl = compute_ttl(start_time.as_deref(), stale_time.as_deref());

    Ok(CotEvent {
        uid,
        event_type,
        destination,
        message_type,
        position,
        ttl,
        source_group,
    })
}

fn parse_f64(value: &str, field: &'static str) -> Result<f64, ParseError> {
    value.parse().ok().ok_or(ParseError::InvalidFloat(field))
}

/// Reject values outside `[min, max]` (inclusive).
///
/// Non-finite values (NaN, ±∞) are also rejected — `f64::parse` normally
/// returns `Err` for `"NaN"` / `"inf"` but checks here make the invariant
/// explicit and future-proof the parser against permissive float grammars.
fn check_range(field: &'static str, value: f64, min: f64, max: f64) -> Result<(), ParseError> {
    if !value.is_finite() || !(min..=max).contains(&value) {
        return Err(ParseError::OutOfRange { field, value });
    }
    Ok(())
}

fn map_event_type(cot_type: &str) -> MessageType {
    if cot_type.starts_with("a-") {
        MessageType::Position
    } else if cot_type.starts_with("b-t-f") {
        MessageType::Chat
    } else if cot_type.starts_with("b-a") {
        MessageType::Alert
    } else {
        MessageType::Other(cot_type.to_string())
    }
}

fn compute_ttl(start: Option<&str>, stale: Option<&str>) -> Option<Duration> {
    let start = start?;
    let stale = stale?;

    let start_dt = parse_iso8601(start)?;
    let stale_dt = parse_iso8601(stale)?;

    stale_dt.checked_sub(start_dt).map(Duration::from_secs)
}

fn parse_iso8601(s: &str) -> Option<u64> {
    // Minimal ISO8601 parser: 2021-02-27T20:32:24.771Z
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;

    // Validate ranges to prevent overflow in epoch calculation.
    if !(0..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let time = time.split('.').next()?;
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let min: i64 = time_parts.next()?.parse().ok()?;
    let sec: i64 = time_parts.next()?.parse().ok()?;

    if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=59).contains(&sec) {
        return None;
    }

    // Rough epoch calculation (not accounting for leap years properly, but good enough for TTL).
    // With year bounded to 0..=9999, these operations cannot overflow i64.
    let days_since_epoch = (year - 1970) * 365 + (year - 1969) / 4 + day_of_year(month, day);
    if days_since_epoch < 0 {
        return None;
    }
    Some(days_since_epoch as u64 * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64)
}

fn day_of_year(month: i64, day: i64) -> i64 {
    const DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    DAYS.get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or(0)
        + day
}

// ── message builder ─────────────────────────────────────────────────────

/// Builds [`RoutableMessage`]s from raw payload bytes.
///
/// Handles CoT parsing, destination extraction, source identity enrichment,
/// and sticky session-group tracking across messages within a session.
///
/// Position CoT events carry `<__group name="Cyan"/>` but chat and other
/// types don't. `MessageBuilder` caches the group from the first position
/// message and applies it to subsequent messages from the same session,
/// keeping NATS group routing correct even for non-position payloads.
#[derive(Default)]
pub struct MessageBuilder {
    session_group: Option<String>,
    /// Optional callback invoked once per legacy-version SA payload that
    /// the builder upgrades to [`CURRENT_SA_VERSION`]. Wired by the
    /// server crate to feed the
    /// `rustgate_sa_auto_upgraded_total{from_version}` Prometheus
    /// counter without making `rustgate-cot` depend on the metrics
    /// layer. Closes #741.
    on_sa_upgraded: Option<OnSaAutoUpgraded>,
    /// Refs #849: per-listener default CAPCO classification banner.
    /// When set, every built message that does not already carry a
    /// `Metadata.classification` is stamped with this marking before
    /// being returned. `None` (default) keeps pre-#849 behaviour:
    /// unmarked traffic flows unchanged.
    default_classification: Option<rustgate_core::classification::ClassificationMarking>,
}

impl std::fmt::Debug for MessageBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageBuilder")
            .field("session_group", &self.session_group)
            .field("on_sa_upgraded_installed", &self.on_sa_upgraded.is_some())
            .field(
                "default_classification",
                &self.default_classification.as_ref().map(|m| m.to_string()),
            )
            .finish()
    }
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the SA auto-upgrade observer. The callback fires once
    /// per upgraded payload with the `from_version` label
    /// (`"v1"` or `"v2-pre-2.0"`); see [`OnSaAutoUpgraded`] for the
    /// operational rationale. Subsequent calls replace the previous
    /// observer.
    pub fn with_on_sa_upgraded(mut self, cb: OnSaAutoUpgraded) -> Self {
        self.on_sa_upgraded = Some(cb);
        self
    }

    /// Refs #849: install a per-listener default CAPCO classification
    /// marking. Every message produced by [`Self::build`] that does
    /// not already carry a `Metadata.classification` will be stamped
    /// with this marking before being returned. Subsequent calls
    /// replace the previous default.
    #[must_use]
    pub fn with_default_classification(
        mut self,
        marking: rustgate_core::classification::ClassificationMarking,
    ) -> Self {
        self.default_classification = Some(marking);
        self
    }

    /// Parse payload bytes and build a routable message.
    ///
    /// If the payload is valid CoT XML, extracts destination, message type,
    /// and TTL from the CoT event. Otherwise falls back to broadcast with
    /// `MessageType::Other("raw")`.
    ///
    /// `source_protocol` identifies the transport origin (e.g. `"tcp"`, `"websocket"`).
    ///
    /// When a [`OnSaAutoUpgraded`] callback is installed via
    /// [`with_on_sa_upgraded`](Self::with_on_sa_upgraded), payloads
    /// emitted with a legacy `<event version=…>` value are rewritten
    /// to [`CURRENT_SA_VERSION`] before downstream parsing and the
    /// callback fires once per upgrade with the `from_version` label.
    pub fn build(
        &mut self,
        identity: &Identity,
        payload: Bytes,
        source_protocol: &str,
    ) -> RoutableMessage {
        // SA auto-upgrade: when an observer is installed, lift legacy
        // version strings to the current envelope before parsing so
        // downstream consumers (NATS bridge, federation) only ever see
        // the modern shape. See #741: the upgrade was previously silent.
        let payload = match self.on_sa_upgraded.as_ref() {
            Some(cb) => {
                let cb = Arc::clone(cb);
                auto_upgrade_sa_version(payload, |label| cb(label))
            }
            None => payload,
        };
        let mut msg = match parse(&payload) {
            Ok(cot) => {
                if cot.source_group.is_some() {
                    self.session_group = cot.source_group.clone();
                }
                self.build_from_cot(identity, payload, source_protocol, cot)
            }
            Err(_) => self.build_raw(identity, payload, source_protocol),
        };
        // Refs #849 item 4: stamp the per-listener default
        // classification when configured and the message does not
        // already carry one. The CoT path could in principle parse a
        // `<marking>` element from the payload in a future iteration;
        // until then the field is `None` after `build_from_cot` /
        // `build_raw` and the default applies unconditionally.
        if let Some(ref default) = self.default_classification
            && msg.metadata.classification.is_none()
        {
            msg.metadata = msg.metadata.with_classification(default.clone());
        }
        msg
    }

    fn build_from_cot(
        &self,
        source: &Identity,
        payload: Bytes,
        source_protocol: &str,
        cot: CotEvent,
    ) -> RoutableMessage {
        let destination = match cot.destination {
            CotDestination::Broadcast => Destination::Broadcast,
            CotDestination::Group(name) => Destination::Group(name.into()),
            CotDestination::Callsign(cn) => {
                // Destination identities are used for routing lookup by CN only;
                // they have no TLS session, so use the plaintext constructor.
                match Identity::plaintext(cn, BTreeSet::new()) {
                    Ok(id) => Destination::Direct(id),
                    Err(_) => Destination::Broadcast,
                }
            }
        };

        let enriched_source = self.enrich_source(source, cot.source_group.as_ref());

        let mut metadata = Metadata::new(
            SystemTime::now(),
            source_protocol.to_string(),
            cot.message_type,
        );
        if let Some(t) = cot.ttl {
            metadata = metadata.with_ttl(t);
        }
        RoutableMessage {
            source: enriched_source,
            destination,
            payload,
            metadata,
            entity: None,
        }
    }

    fn build_raw(
        &self,
        source: &Identity,
        payload: Bytes,
        source_protocol: &str,
    ) -> RoutableMessage {
        let enriched_source = self.enrich_source(source, None);

        RoutableMessage {
            source: enriched_source,
            destination: Destination::Broadcast,
            payload,
            metadata: Metadata::new(
                SystemTime::now(),
                source_protocol.to_string(),
                MessageType::Other("raw".into()),
            ),
            entity: None,
        }
    }

    fn enrich_source(&self, source: &Identity, cot_group: Option<&String>) -> Identity {
        let mut enriched = source.clone();
        let group = cot_group.or(self.session_group.as_ref());
        if let Some(g) = group {
            let _ = enriched.groups.insert(g.clone());
        }
        enriched
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_optional_ce_le_and_ignores_malformed_values() {
        let with = br#"<event version="2.0" uid="u" type="a-f-G" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T00:05:00Z" how="m-g"><point lat="1" lon="2" hae="3" ce="9999999" le="4.5"/></event>"#;
        let pos = parse(with).unwrap().position.unwrap();
        assert_eq!(pos.ce, Some(9_999_999.0));
        assert_eq!(pos.le, Some(4.5));

        // Malformed ce/le must not reject the event (they were never
        // validated before this field existed).
        let bad = br#"<event version="2.0" uid="u" type="a-f-G" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T00:05:00Z" how="m-g"><point lat="1" lon="2" hae="3" ce="n/a"/></event>"#;
        let pos = parse(bad).unwrap().position.unwrap();
        assert_eq!(pos.ce, None);
        assert_eq!(pos.le, None);

        let non_finite = br#"<event version="2.0" uid="u" type="a-f-G" time="2026-01-01T00:00:00Z" start="2026-01-01T00:00:00Z" stale="2026-01-01T00:05:00Z" how="m-g"><point lat="1" lon="2" hae="3" ce="NaN" le="inf"/></event>"#;
        let pos = parse(non_finite).unwrap().position.unwrap();
        assert_eq!(pos.ce, None);
        assert_eq!(pos.le, None);
    }

    fn test_identity() -> Identity {
        Identity::new("alice".into(), "abc123".into(), BTreeSet::new()).unwrap()
    }

    fn position_xml(group: Option<&str>) -> Vec<u8> {
        let group_tag = group
            .map(|g| format!("<__group name=\"{g}\"/>"))
            .unwrap_or_default();
        format!(
            r#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail>{group_tag}</detail></event>"#,
        )
        .into_bytes()
    }

    fn chat_xml_direct(callsign: &str) -> Vec<u8> {
        format!(
            r#"<event uid="u2" type="b-t-f" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="0" lon="0" hae="0"/><detail><dest callsign="{callsign}"/></detail></event>"#,
        )
        .into_bytes()
    }

    fn cot_with_group_dest(group: &str) -> Vec<u8> {
        format!(
            r#"<event uid="u3" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail><dest group="{group}"/></detail></event>"#,
        )
        .into_bytes()
    }

    #[test]
    fn cot_broadcast() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from(position_xml(Some("Cyan")));
        let msg = builder.build(&id, payload, "tcp");

        assert!(matches!(msg.destination, Destination::Broadcast));
        assert_eq!(msg.metadata.message_type, MessageType::Position);
        assert!(msg.source.groups.contains("Cyan"));
    }

    #[test]
    fn cot_direct() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from(chat_xml_direct("bob"));
        let msg = builder.build(&id, payload, "tcp");

        match &msg.destination {
            Destination::Direct(target) => assert_eq!(&*target.cn, "bob"),
            other => panic!("expected Direct, got {other:?}"),
        }
    }

    #[test]
    fn cot_group() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from(cot_with_group_dest("alpha"));
        let msg = builder.build(&id, payload, "tcp");

        match &msg.destination {
            Destination::Group(name) => assert_eq!(&**name, "alpha"),
            other => panic!("expected Group, got {other:?}"),
        }
    }

    #[test]
    fn non_cot_fallback() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from_static(b"not xml at all");
        let msg = builder.build(&id, payload, "tcp");

        assert!(matches!(msg.destination, Destination::Broadcast));
        assert_eq!(msg.metadata.message_type, MessageType::Other("raw".into()));
    }

    #[test]
    fn session_group_sticky() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();

        // First message: position with group
        let pos = Bytes::from(position_xml(Some("Cyan")));
        let msg1 = builder.build(&id, pos, "tcp");
        assert!(msg1.source.groups.contains("Cyan"));

        // Second message: chat without group — should still have Cyan
        let chat = Bytes::from(chat_xml_direct("bob"));
        let msg2 = builder.build(&id, chat, "tcp");
        assert!(
            msg2.source.groups.contains("Cyan"),
            "session group should be sticky across messages"
        );
    }

    #[test]
    fn source_protocol_stamped() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from_static(b"raw");
        let msg = builder.build(&id, payload, "websocket");

        assert_eq!(msg.metadata.source_protocol, "websocket");
    }

    #[test]
    fn source_protocol_for_cot() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from(position_xml(Some("Cyan")));
        let msg = builder.build(&id, payload, "tcp");

        assert_eq!(
            msg.metadata.source_protocol, "tcp",
            "CoT messages should carry transport protocol, not 'cot'"
        );
    }

    #[test]
    fn non_cot_preserves_source_protocol() {
        let id = test_identity();
        let mut builder = MessageBuilder::new();
        let payload = Bytes::from_static(b"raw bytes");
        let msg = builder.build(&id, payload, "tcp");

        assert_eq!(msg.metadata.source_protocol, "tcp");
    }

    // ── parse_iso8601 regression tests (issue #370) ──────────────

    #[test]
    fn parse_iso8601_valid() {
        let ts = parse_iso8601("2021-02-27T20:32:24.771Z");
        assert!(ts.is_some());
    }

    #[test]
    fn parse_iso8601_extreme_year_returns_none() {
        // Previously caused integer overflow panic in debug builds.
        assert!(parse_iso8601("25252525252525252-01-01T00:00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_negative_year_returns_none() {
        assert!(parse_iso8601("-9999999999-01-01T00:00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_month_out_of_range() {
        assert!(parse_iso8601("2021-13-01T00:00:00Z").is_none());
        assert!(parse_iso8601("2021-00-01T00:00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_day_out_of_range() {
        assert!(parse_iso8601("2021-01-32T00:00:00Z").is_none());
        assert!(parse_iso8601("2021-01-00T00:00:00Z").is_none());
    }

    #[test]
    fn parse_iso8601_time_out_of_range() {
        assert!(parse_iso8601("2021-01-01T24:00:00Z").is_none());
        assert!(parse_iso8601("2021-01-01T00:60:00Z").is_none());
        assert!(parse_iso8601("2021-01-01T00:00:60Z").is_none());
    }

    // ── WGS-84 lat/lon range tests ──────────────────────────────────

    fn point_xml(lat: &str, lon: &str) -> Vec<u8> {
        format!(
            r#"<event uid="u" type="a-f-G" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="{lat}" lon="{lon}" hae="0"/></event>"#,
        )
        .into_bytes()
    }

    #[test]
    fn parse_accepts_boundary_lat_lon() {
        // Exact WGS-84 extremes per MP090284 Table 2-1 must parse.
        for (lat, lon) in [("-90", "-180"), ("90", "180"), ("0", "0")] {
            assert!(
                parse(&point_xml(lat, lon)).is_ok(),
                "boundary ({lat}, {lon})"
            );
        }
    }

    #[test]
    fn parse_rejects_out_of_range_lat() {
        let err = parse(&point_xml("90.0001", "0")).expect_err("lat > 90");
        assert!(matches!(err, ParseError::OutOfRange { field: "lat", .. }));

        let err = parse(&point_xml("-90.5", "0")).expect_err("lat < -90");
        assert!(matches!(err, ParseError::OutOfRange { field: "lat", .. }));
    }

    #[test]
    fn parse_rejects_out_of_range_lon() {
        let err = parse(&point_xml("0", "180.1")).expect_err("lon > 180");
        assert!(matches!(err, ParseError::OutOfRange { field: "lon", .. }));

        let err = parse(&point_xml("0", "-273.5")).expect_err("lon < -180");
        assert!(matches!(err, ParseError::OutOfRange { field: "lon", .. }));
    }

    #[test]
    fn check_range_rejects_non_finite() {
        assert!(matches!(
            check_range("lat", f64::NAN, -90.0, 90.0),
            Err(ParseError::OutOfRange { field: "lat", .. })
        ));
        assert!(matches!(
            check_range("lon", f64::INFINITY, -180.0, 180.0),
            Err(ParseError::OutOfRange { field: "lon", .. })
        ));
        assert!(matches!(
            check_range("lon", f64::NEG_INFINITY, -180.0, 180.0),
            Err(ParseError::OutOfRange { field: "lon", .. })
        ));
    }

    // ── SA event type detection tests ────────────────────────────────

    #[test]
    fn is_sa_event_friendly() {
        assert!(is_sa_event("a-f-G-U-C"));
        assert!(is_sa_event("a-f-A"));
        assert!(is_sa_event("a-f-G"));
    }

    #[test]
    fn is_sa_event_hostile() {
        assert!(is_sa_event("a-h-G"));
        assert!(is_sa_event("a-h-A-M-F"));
    }

    #[test]
    fn is_sa_event_neutral() {
        assert!(is_sa_event("a-n-G"));
    }

    #[test]
    fn is_sa_event_unknown() {
        assert!(is_sa_event("a-u-G"));
    }

    #[test]
    fn is_sa_event_rejects_non_sa() {
        assert!(!is_sa_event("b-t-f"));
        assert!(!is_sa_event("t-x-d"));
        assert!(!is_sa_event("b-a-o-tbl"));
        assert!(!is_sa_event("a-"));
        assert!(!is_sa_event(""));
        // Unknown affiliation character (not one of p/a/f/n/s/h/j/k/u/o/x).
        assert!(!is_sa_event("a-z-G"));
        assert!(!is_sa_event("a-q-G"));
    }

    #[test]
    fn sa_affiliation_covers_full_appendix_a() {
        // MITRE MP090284 Appendix A / Figure 2-3 affiliation codes, aligned
        // with MIL-STD-2525 standard identity.
        assert_eq!(sa_affiliation("a-p-G"), Some(SaAffiliation::Pending));
        assert_eq!(sa_affiliation("a-a-G"), Some(SaAffiliation::AssumedFriend));
        assert_eq!(sa_affiliation("a-f-G-U-C"), Some(SaAffiliation::Friend));
        assert_eq!(sa_affiliation("a-n-G"), Some(SaAffiliation::Neutral));
        assert_eq!(sa_affiliation("a-s-G"), Some(SaAffiliation::Suspect));
        assert_eq!(sa_affiliation("a-h-G"), Some(SaAffiliation::Hostile));
        assert_eq!(sa_affiliation("a-j-G"), Some(SaAffiliation::Joker));
        assert_eq!(sa_affiliation("a-k-G"), Some(SaAffiliation::Faker));
        assert_eq!(sa_affiliation("a-u-G"), Some(SaAffiliation::Unknown));
        assert_eq!(sa_affiliation("a-o-G"), Some(SaAffiliation::NoneSpecified));
        assert_eq!(sa_affiliation("a-x-G"), Some(SaAffiliation::Other));
    }

    #[test]
    fn is_sa_event_accepts_all_appendix_a_affiliations() {
        for code in ['p', 'a', 'f', 'n', 's', 'h', 'j', 'k', 'u', 'o', 'x'] {
            let t = format!("a-{code}-G");
            assert!(is_sa_event(&t), "expected SA atom for {t}");
        }
    }

    #[test]
    fn sa_affiliation_none_for_non_sa() {
        assert_eq!(sa_affiliation("b-t-f"), None);
        assert_eq!(sa_affiliation("t-x-d"), None);
        assert_eq!(sa_affiliation(""), None);
        assert_eq!(sa_affiliation("a-"), None);
        // Outside the Appendix A character set.
        assert_eq!(sa_affiliation("a-z-G"), None);
        assert_eq!(sa_affiliation("a-q-G"), None);
    }

    #[test]
    fn sa_affiliation_edge_cases() {
        // Too short to contain a valid affiliation
        assert_eq!(sa_affiliation("a"), None);
        assert_eq!(sa_affiliation("a-f"), None);
        // Missing trailing dash (not a valid SA atom)
        assert_eq!(sa_affiliation("a-fx"), None);
    }

    // ── how= taxonomy tests (MP090284 §C) ────────────────────────────

    #[test]
    fn how_origin_classifies_machine() {
        assert_eq!(how_origin("m-g"), HowOrigin::Machine);
        assert_eq!(how_origin("m-g-a"), HowOrigin::Machine);
        assert_eq!(how_origin("m-g-n"), HowOrigin::Machine);
        assert_eq!(how_origin("m-r"), HowOrigin::Machine);
        // Unknown sub-type is still machine-origin — classifier is permissive.
        assert_eq!(how_origin("m-zzz"), HowOrigin::Machine);
    }

    #[test]
    fn how_origin_classifies_human() {
        assert_eq!(how_origin("h-e"), HowOrigin::Human);
        assert_eq!(how_origin("h-g-i-g-o"), HowOrigin::Human);
        assert_eq!(how_origin("h-p"), HowOrigin::Human);
        // Unknown sub-type is still human-origin.
        assert_eq!(how_origin("h-zzz"), HowOrigin::Human);
    }

    #[test]
    fn how_origin_other_for_non_conforming() {
        assert_eq!(how_origin(""), HowOrigin::Other);
        assert_eq!(how_origin("unknown"), HowOrigin::Other);
        assert_eq!(how_origin("x-y-z"), HowOrigin::Other);
        // Missing dash separator after the origin character.
        assert_eq!(how_origin("mg"), HowOrigin::Other);
        assert_eq!(how_origin("he"), HowOrigin::Other);
        // Bare single-char origin is not enough.
        assert_eq!(how_origin("m"), HowOrigin::Other);
        assert_eq!(how_origin("h"), HowOrigin::Other);
    }

    #[test]
    fn how_origin_is_case_sensitive() {
        // TAK `how` values are lowercase by convention; uppercase is non-conforming.
        assert_eq!(how_origin("M-G"), HowOrigin::Other);
        assert_eq!(how_origin("H-E"), HowOrigin::Other);
    }

    #[test]
    fn how_is_spec_conformant_accepts_all_machine_values() {
        for value in ["m-g", "m-g-a", "m-g-n", "m-f", "m-n", "m-r", "m-i"] {
            assert!(
                how_is_spec_conformant(value),
                "expected {value} to be spec-conformant"
            );
        }
    }

    #[test]
    fn how_is_spec_conformant_accepts_all_human_values() {
        for value in ["h-e", "h-g-i-g-o", "h-t", "h-s", "h-p", "h-c"] {
            assert!(
                how_is_spec_conformant(value),
                "expected {value} to be spec-conformant"
            );
        }
    }

    #[test]
    fn how_is_spec_conformant_rejects_unknown_subtypes() {
        // Correct origin prefix but sub-type not in the MP090284 list.
        assert!(!how_is_spec_conformant("m-zzz"));
        assert!(!how_is_spec_conformant("h-zzz"));
        assert!(!how_is_spec_conformant("m-g-x"));
    }

    #[test]
    fn how_is_spec_conformant_rejects_non_origin_strings() {
        assert!(!how_is_spec_conformant(""));
        assert!(!how_is_spec_conformant("unknown"));
        assert!(!how_is_spec_conformant("x-y-z"));
    }

    #[test]
    fn how_is_spec_conformant_is_case_sensitive() {
        assert!(!how_is_spec_conformant("M-G"));
        assert!(!how_is_spec_conformant("H-E"));
    }

    // ── SA auto-upgrade (issue #741) ─────────────────────────────

    #[test]
    fn classify_legacy_sa_version_v1_when_attribute_missing() {
        let payload = br#"<event uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#;
        assert_eq!(classify_legacy_sa_version(payload), Some("v1"));
    }

    #[test]
    fn classify_legacy_sa_version_pre_2_0_when_value_below_2() {
        let payload = br#"<event version="1.0" uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#;
        assert_eq!(classify_legacy_sa_version(payload), Some("v2-pre-2.0"));
    }

    #[test]
    fn classify_legacy_sa_version_none_for_current_version() {
        let payload =
            br#"<event version="2.0" uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#;
        assert_eq!(classify_legacy_sa_version(payload), None);
    }

    #[test]
    fn classify_legacy_sa_version_none_for_future_version() {
        let payload =
            br#"<event version="3.0" uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#;
        assert_eq!(classify_legacy_sa_version(payload), None);
    }

    #[test]
    fn classify_legacy_sa_version_none_for_non_xml() {
        assert_eq!(classify_legacy_sa_version(b"not xml at all"), None);
    }

    #[test]
    fn classify_legacy_sa_version_distinguishes_eventlog() {
        // `<eventLog>` must NOT match `<event>` — the attribute scanner
        // requires a word boundary after the tag name.
        let payload = br#"<eventLog uid="x"><entry/></eventLog>"#;
        assert_eq!(classify_legacy_sa_version(payload), None);
    }

    #[test]
    fn auto_upgrade_sa_v1_inserts_version_attribute() {
        let observed = std::sync::Mutex::new(None::<String>);
        let cb = |label: &str| {
            *observed.lock().unwrap() = Some(label.to_string());
        };
        let payload = Bytes::from_static(
            br#"<event uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#,
        );
        let upgraded = auto_upgrade_sa_version(payload, cb);
        assert_eq!(observed.lock().unwrap().as_deref(), Some("v1"));
        let upgraded_str = std::str::from_utf8(&upgraded).unwrap();
        assert!(
            upgraded_str.contains(r#"version="2.0""#),
            "v1 upgrade must insert version=2.0; got: {upgraded_str}"
        );
    }

    #[test]
    fn auto_upgrade_sa_pre_2_0_rewrites_version_attribute() {
        let observed = std::sync::Mutex::new(None::<String>);
        let cb = |label: &str| {
            *observed.lock().unwrap() = Some(label.to_string());
        };
        let payload = Bytes::from_static(
            br#"<event version="1.0" uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#,
        );
        let upgraded = auto_upgrade_sa_version(payload, cb);
        assert_eq!(observed.lock().unwrap().as_deref(), Some("v2-pre-2.0"));
        let upgraded_str = std::str::from_utf8(&upgraded).unwrap();
        assert!(
            upgraded_str.contains(r#"version="2.0""#),
            "pre-2.0 upgrade must rewrite to version=2.0; got: {upgraded_str}"
        );
        assert!(
            !upgraded_str.contains(r#"version="1.0""#),
            "pre-2.0 upgrade must replace the old version; got: {upgraded_str}"
        );
    }

    #[test]
    fn auto_upgrade_sa_no_callback_fires_when_current() {
        let observed = std::sync::Mutex::new(0usize);
        let cb = |_: &str| {
            *observed.lock().unwrap() += 1;
        };
        let payload = Bytes::from_static(
            br#"<event version="2.0" uid="x" type="a-f-G"><point lat="0" lon="0" hae="0"/></event>"#,
        );
        let after = auto_upgrade_sa_version(payload.clone(), cb);
        assert_eq!(*observed.lock().unwrap(), 0);
        assert_eq!(after, payload, "current-version payload must be untouched");
    }

    #[test]
    fn sa_v1_payload_invokes_upgraded_callback_with_v1_label() {
        // End-to-end through MessageBuilder: a v1 SA payload (no
        // version attribute) is upgraded and the callback fires with
        // the "v1" label exactly once.
        let counter: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let counter_cb = Arc::clone(&counter);
        let cb: OnSaAutoUpgraded = Arc::new(move |label: &str| {
            counter_cb.lock().push(label.to_string());
        });

        let id = test_identity();
        let mut builder = MessageBuilder::new().with_on_sa_upgraded(cb);
        // SA atom (a-f-G-U-C) without a version attribute.
        let payload = Bytes::from_static(
            br#"<event uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail/></event>"#,
        );
        let _ = builder.build(&id, payload, "tcp");
        let observed = counter.lock().clone();
        assert_eq!(
            observed,
            vec!["v1".to_string()],
            "v1 SA payload must invoke the upgrade callback exactly once with the \"v1\" label"
        );
    }

    #[test]
    fn sa_pre_2_0_payload_invokes_upgraded_callback_with_pre_label() {
        let counter: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let counter_cb = Arc::clone(&counter);
        let cb: OnSaAutoUpgraded = Arc::new(move |label: &str| {
            counter_cb.lock().push(label.to_string());
        });

        let id = test_identity();
        let mut builder = MessageBuilder::new().with_on_sa_upgraded(cb);
        let payload = Bytes::from_static(
            br#"<event version="1.0" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail/></event>"#,
        );
        let _ = builder.build(&id, payload, "tcp");
        assert_eq!(counter.lock().clone(), vec!["v2-pre-2.0".to_string()]);
    }

    #[test]
    fn sa_current_payload_does_not_invoke_upgrade_callback() {
        let counter: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let counter_cb = Arc::clone(&counter);
        let cb: OnSaAutoUpgraded = Arc::new(move |label: &str| {
            counter_cb.lock().push(label.to_string());
        });

        let id = test_identity();
        let mut builder = MessageBuilder::new().with_on_sa_upgraded(cb);
        let payload = Bytes::from_static(
            br#"<event version="2.0" uid="u1" type="a-f-G-U-C" start="2024-01-01T00:00:00Z" stale="2024-01-01T00:05:00Z"><point lat="38.0" lon="-77.0" hae="0.0"/><detail/></event>"#,
        );
        let _ = builder.build(&id, payload, "tcp");
        assert!(
            counter.lock().is_empty(),
            "current-version SA payload must not invoke the upgrade callback"
        );
    }
}
