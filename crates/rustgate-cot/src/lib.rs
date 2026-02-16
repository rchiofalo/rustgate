//! Cursor on Target (CoT) XML parser.

use std::time::Duration;

use rustgate_core::message::{Destination, MessageType};

#[derive(Debug, Clone)]
pub struct CotEvent {
    pub uid: String,
    pub event_type: String,
    pub destination: Destination,
    pub message_type: MessageType,
    pub position: Option<Position>,
    pub ttl: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct Position {
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidXml,
    MissingField(&'static str),
}

pub fn parse(_xml: &[u8]) -> Result<CotEvent, ParseError> {
    todo!()
}
