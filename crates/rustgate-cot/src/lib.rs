// Copyright © 2026 Roberto Chiofalo.

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

pub mod delta;
pub mod mask;

use std::collections::BTreeSet;
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
}

/// Errors that can occur when parsing CoT XML.
#[derive(Debug)]
pub enum ParseError {
    Xml(quick_xml::Error),
    MissingAttribute(&'static str),
    InvalidFloat(&'static str),
    /// A numeric field was out of its spec-defined range.
    ///
    /// MITRE CoT Message Router User's Guide (MP090284) Table 2-1 defines
    /// `lat` and `lon` in WGS-84 decimal degrees: latitude -90..=90,
    /// longitude -180..=180. Values outside these ranges are rejected
    /// rather than propagated to downstream geofilter / multicast logic.
    OutOfRange {
        field: &'static str,
        value: f64,
    },
}

impl From<quick_xml::Error> for ParseError {
    fn from(e: quick_xml::Error) -> Self {
        ParseError::Xml(e)
    }
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
pub fn parse(xml: &[u8]) -> Result<CotEvent, ParseError> {
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
                b"event" => {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"uid" => uid = Some(String::from_utf8_lossy(&attr.value).into_owned()),
                            b"type" => {
                                event_type = Some(String::from_utf8_lossy(&attr.value).into_owned())
                            }
                            b"stale" => {
                                stale_time = Some(String::from_utf8_lossy(&attr.value).into_owned())
                            }
                            b"start" => {
                                start_time = Some(String::from_utf8_lossy(&attr.value).into_owned())
                            }
                            _ => {}
                        }
                    }
                }
                b"point" => {
                    let mut lat = None;
                    let mut lon = None;
                    let mut hae = None;
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"lat" => {
                                let v = parse_f64(&attr.value, "lat")?;
                                check_range("lat", v, -90.0, 90.0)?;
                                lat = Some(v);
                            }
                            b"lon" => {
                                let v = parse_f64(&attr.value, "lon")?;
                                check_range("lon", v, -180.0, 180.0)?;
                                lon = Some(v);
                            }
                            b"hae" => hae = Some(parse_f64(&attr.value, "hae")?),
                            _ => {}
                        }
                    }
                    if let (Some(lat), Some(lon), Some(hae)) = (lat, lon, hae) {
                        position = Some(Position { lat, lon, hae });
                    }
                }
                b"dest" => {
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"callsign" => {
                                dest_callsign =
                                    Some(String::from_utf8_lossy(&attr.value).into_owned())
                            }
                            b"group" => {
                                dest_group = Some(String::from_utf8_lossy(&attr.value).into_owned())
                            }
                            _ => {}
                        }
                    }
                }
                b"__group" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            source_group = Some(String::from_utf8_lossy(&attr.value).into_owned());
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

fn parse_f64(value: &[u8], field: &'static str) -> Result<f64, ParseError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(ParseError::InvalidFloat(field))
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
#[derive(Debug, Default)]
pub struct MessageBuilder {
    session_group: Option<String>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse payload bytes and build a routable message.
    ///
    /// If the payload is valid CoT XML, extracts destination, message type,
    /// and TTL from the CoT event. Otherwise falls back to broadcast with
    /// `MessageType::Other("raw")`.
    ///
    /// `source_protocol` identifies the transport origin (e.g. `"tcp"`, `"websocket"`).
    pub fn build(
        &mut self,
        identity: &Identity,
        payload: Bytes,
        source_protocol: &str,
    ) -> RoutableMessage {
        match parse(&payload) {
            Ok(cot) => {
                if cot.source_group.is_some() {
                    self.session_group = cot.source_group.clone();
                }
                self.build_from_cot(identity, payload, source_protocol, cot)
            }
            Err(_) => self.build_raw(identity, payload, source_protocol),
        }
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
            CotDestination::Group(name) => Destination::Group(name),
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

        RoutableMessage {
            source: enriched_source,
            destination,
            payload,
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: source_protocol.to_string(),
                message_type: cot.message_type,
                ttl: cot.ttl,
            },
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
            metadata: Metadata {
                received_at: SystemTime::now(),
                source_protocol: source_protocol.to_string(),
                message_type: MessageType::Other("raw".into()),
                ttl: None,
            },
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
            Destination::Direct(target) => assert_eq!(target.cn, "bob"),
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
            Destination::Group(name) => assert_eq!(name, "alpha"),
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
}
