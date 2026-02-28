//! Cursor on Target (CoT) XML parser.
//!
//! # Security
//!
//! This parser uses `quick-xml`, a streaming parser that does not resolve
//! external entities or process DTD declarations. This design prevents
//! XXE (XML External Entity) injection attacks by default.

use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::Reader;
use rustgate_core::message::MessageType;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CotDestination {
    Broadcast,
    Callsign(String),
    Group(String),
}

#[derive(Debug, Clone, Copy)]
pub struct Position {
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
}

#[derive(Debug)]
pub enum ParseError {
    Xml(quick_xml::Error),
    MissingAttribute(&'static str),
    InvalidFloat(&'static str),
}

impl From<quick_xml::Error> for ParseError {
    fn from(e: quick_xml::Error) -> Self {
        ParseError::Xml(e)
    }
}

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
            Event::Start(e) | Event::Empty(e) => {
                match e.name().as_ref() {
                    b"event" => {
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"uid" => uid = Some(String::from_utf8_lossy(&attr.value).into_owned()),
                                b"type" => event_type = Some(String::from_utf8_lossy(&attr.value).into_owned()),
                                b"stale" => stale_time = Some(String::from_utf8_lossy(&attr.value).into_owned()),
                                b"start" => start_time = Some(String::from_utf8_lossy(&attr.value).into_owned()),
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
                                b"lat" => lat = Some(parse_f64(&attr.value, "lat")?),
                                b"lon" => lon = Some(parse_f64(&attr.value, "lon")?),
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
                                b"callsign" => dest_callsign = Some(String::from_utf8_lossy(&attr.value).into_owned()),
                                b"group" => dest_group = Some(String::from_utf8_lossy(&attr.value).into_owned()),
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
                }
            }
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

    let time = time.split('.').next()?;
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let min: i64 = time_parts.next()?.parse().ok()?;
    let sec: i64 = time_parts.next()?.parse().ok()?;

    // Rough epoch calculation (not accounting for leap years properly, but good enough for TTL)
    let days_since_epoch = (year - 1970) * 365 + (year - 1969) / 4 + day_of_year(month, day);
    Some(days_since_epoch as u64 * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64)
}

fn day_of_year(month: i64, day: i64) -> i64 {
    const DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    DAYS.get(month.saturating_sub(1) as usize).copied().unwrap_or(0) + day
}
