// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

//! Hand-rolled protobuf wire-format primitives and the typed
//! [`TakPacket`] / [`Pli`] / [`GeoChat`] message structs used by
//! the Meshtastic LoRa codec.
//!
//! # Why hand-rolled
//!
//! The Meshtastic `TAKPacket` schema is small (one top-level message
//! with a three-arm `oneof`, two nested messages, and a handful of
//! scalar fields). Adding a `build.rs` + `prost` dependency for that
//! surface would dwarf the crate it produces. Hand-rolled wire-format
//! parsing keeps the dependency footprint at `bytes` + `thiserror` +
//! `rustgate-core` and surfaces every wire-tag mistake at the read
//! site rather than behind generated code. The parser is forward-
//! compatible: unknown fields are skipped (the canonical protobuf
//! "ignore unknown" behaviour) so a future schema revision that adds
//! fields stays decodable.
//!
//! # Wire layout
//!
//! ```text
//! TAKPacket {
//!     1 bool  is_compressed
//!     2 group bytes(?)               // Contact (callsign + role)
//!     3 group bytes(?)               // Group   (team + role)
//!     4 group bytes(?)               // Status  (battery + status flags)
//!     // oneof payload_variant:
//!     5 PLI       pli                // length-delimited submessage
//!     6 GeoChat   chat               // length-delimited submessage
//!     7 bytes     detail             // length-delimited opaque CoT detail
//! }
//!
//! PLI {
//!     1 sfixed32 latitude_i          // lat × 1e7
//!     2 sfixed32 longitude_i         // lon × 1e7
//!     3 int32    altitude            // metres (HAE), signed
//!     4 uint32   speed               // cm/s
//!     5 uint32   course              // degrees × 100
//! }
//! ```
//!
//! Field tags are computed as `(field_number << 3) | wire_type`. Wire
//! types used here: 0 = varint, 2 = length-delimited, 5 = fixed32. A
//! `sfixed32` rides on wire type 5 with little-endian byte order; the
//! integer is interpreted as two's-complement (no zig-zag) per the
//! protobuf spec for the `sfixed*` family.
//!
//! # Field pruning
//!
//! Encode is intentionally narrow: every field is omitted when the
//! corresponding [`TakPacket`] field is `None` / empty. The 237-byte
//! transport cap means the encoder cannot afford to emit a default
//! value for every field — the operator-visible budget is the LoRa
//! airtime, and a redundant `is_compressed=false` byte is wasted
//! bandwidth that drops a real PLI report at the tail of a busy
//! window.

use core::fmt;

use bytes::{Buf, BufMut};

use crate::error::MeshtasticError;

/// Maximum wire-format size of any single Meshtastic TAKPacket on
/// the LoRa transport. Mirrors the `MAX_LORA_PAYLOAD_LEN` constant
/// surfaced in upstream Meshtastic firmware. Any encoder output
/// exceeding this is rejected with [`MeshtasticError::PayloadTooLarge`].
///
/// 237 bytes is the post-headers payload after the LoRa PHY header,
/// the Meshtastic mesh header, and the encryption AAD — i.e. the
/// budget the application protocol may consume per frame. Re-exported
/// at the crate root for ergonomic access.
pub const MAX_PAYLOAD_BYTES: usize = 237;

// Field-tag constants. Each tag is `(field_number << 3) | wire_type`;
// pinning them as named constants keeps the parser readable and makes
// schema regressions land at the read site rather than as a silent
// "unknown field, skipped". Wire types: 0 = varint, 2 = length-
// delimited, 5 = fixed32. Tags for varint fields use the bare
// `field << 3` form (low three bits already zero) to keep the
// `identity_op` lint quiet.

// --- TAKPacket fields ---
const TAG_TAK_IS_COMPRESSED: u64 = 1 << 3; // varint
const TAG_TAK_CONTACT: u64 = (2 << 3) | 2; // length-delimited
const TAG_TAK_GROUP: u64 = (3 << 3) | 2; // length-delimited
const TAG_TAK_STATUS: u64 = (4 << 3) | 2; // length-delimited
const TAG_TAK_PLI: u64 = (5 << 3) | 2; // length-delimited
const TAG_TAK_CHAT: u64 = (6 << 3) | 2; // length-delimited
const TAG_TAK_DETAIL: u64 = (7 << 3) | 2; // length-delimited

// --- PLI fields ---
const TAG_PLI_LATITUDE_I: u64 = (1 << 3) | 5; // sfixed32 → wire type 5
const TAG_PLI_LONGITUDE_I: u64 = (2 << 3) | 5; // sfixed32
const TAG_PLI_ALTITUDE: u64 = 3 << 3; // int32 → varint
const TAG_PLI_SPEED: u64 = 4 << 3; // uint32 → varint
const TAG_PLI_COURSE: u64 = 5 << 3; // uint32 → varint

// --- Contact fields (group 2 inside TAKPacket) ---
const TAG_CONTACT_CALLSIGN: u64 = (1 << 3) | 2;
const TAG_CONTACT_DEVICE_CALLSIGN: u64 = (2 << 3) | 2;

// --- Group fields (group 3 inside TAKPacket) ---
const TAG_GROUP_ROLE: u64 = 1 << 3; // varint enum
const TAG_GROUP_TEAM: u64 = 2 << 3; // varint enum

// --- Status fields (group 4 inside TAKPacket) ---
const TAG_STATUS_BATTERY: u64 = 1 << 3; // uint32 → varint

// --- GeoChat fields (group 6 inside TAKPacket) ---
const TAG_CHAT_MESSAGE: u64 = (1 << 3) | 2;
const TAG_CHAT_TO: u64 = (2 << 3) | 2;
const TAG_CHAT_TO_CALLSIGN: u64 = (3 << 3) | 2;

/// Maximum wire bytes the parser will read while skipping an unknown
/// length-delimited field. Keeps a hostile decoder from being forced
/// into a length-prefixed loop that exceeds the 237-byte transport
/// cap by an order of magnitude. The Meshtastic firmware's own
/// budget is the same 237-byte ceiling; a length prefix that exceeds
/// it is by definition malformed.
const MAX_SKIP_LENGTH: usize = MAX_PAYLOAD_BYTES;

/// Top-level Meshtastic TAKPacket message.
///
/// Constructed by the codec's decoder or the higher-level
/// `MeshtasticCodec::from_entity` encode path (see
/// [`crate::codec::MeshtasticCodec`]). All fields are optional on
/// the wire; the codec aggressively prunes any field that is
/// `None` / empty on encode to keep the 237-byte transport cap
/// satisfied.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TakPacket {
    /// Whether the originating device compressed any of the
    /// payload fields (typically the GeoChat body). Carried opaque
    /// — this codec does not implement the upstream compression
    /// scheme.
    pub is_compressed: bool,
    /// Originating-device contact identity (callsign / device-id
    /// pair). `None` when the upstream sender omitted the field.
    pub contact: Option<Contact>,
    /// Originating-device team / role assignment.
    pub group: Option<Group>,
    /// Originating-device runtime status snapshot (battery, …).
    pub status: Option<Status>,
    /// Active payload arm, if any. Mirrors the upstream
    /// `oneof payload_variant`.
    pub payload_variant: Option<PayloadVariant>,
}

/// Contact identity carried in a [`TakPacket`].
///
/// Both fields are length-delimited UTF-8 strings on the wire. The
/// device-callsign is optional — older Meshtastic firmware revisions
/// that predate the field omit it entirely, and a forward-compatible
/// decoder must treat absence as `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Contact {
    /// Operator-visible callsign (e.g. `"Bravo-1"`).
    pub callsign: String,
    /// Device callsign / hardware identifier (e.g. `"!a1b2c3d4"`).
    pub device_callsign: String,
}

/// Team / role assignment carried in a [`TakPacket`].
///
/// Both `role` and `team` are wire-format varints; this codec
/// preserves the raw enum value rather than mapping into a typed
/// enum so a firmware revision that adds new roles / teams stays
/// decodable. Consumers that need symbolic lookup can map at the
/// integration layer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Group {
    /// Member role (e.g. `0=TeamMember`, `1=TeamLead`, …).
    pub role: i32,
    /// Team color enumeration (e.g. `0=White`, `1=Yellow`, …).
    pub team: i32,
}

/// Runtime status snapshot carried in a [`TakPacket`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Status {
    /// Battery state of charge, percent (0..=100).
    pub battery: u32,
}

/// Active payload arm carried in a [`TakPacket`]. Mirrors the
/// upstream `oneof payload_variant` — exactly one variant is set on
/// any wire frame that carries a payload.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadVariant {
    /// Position-Location-Information, the most common payload.
    Pli(Pli),
    /// Free-form geo-chat message addressed to a callsign.
    Chat(GeoChat),
    /// Opaque CoT `<detail>` blob, used for messages whose schema
    /// does not fit the typed `Pli` / `GeoChat` arms.
    Detail(Vec<u8>),
}

/// Position-Location-Information body.
///
/// Coordinate fields ride as scaled integers (the protobuf
/// `sfixed32` wire encoding). The conversion factor (`1e7`) gives
/// ≈ 1.1 cm precision globally — fine for any tactical
/// position. The codec exposes a typed conversion on
/// [`Pli::to_position_floats`] / [`Pli::from_position_floats`] so
/// callers do not need to repeat the magic number.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pli {
    /// Latitude × 1e7 as a signed 32-bit integer. The wire form
    /// is `sfixed32` (little-endian, two's complement).
    pub latitude_i: i32,
    /// Longitude × 1e7 as a signed 32-bit integer. Wire form
    /// is `sfixed32`.
    pub longitude_i: i32,
    /// Altitude HAE in metres, signed. The wire form is `int32`
    /// (varint, NOT `sint32` — no zig-zag). Negative altitudes
    /// (e.g. submarine telemetry, terrain below MSL) consume up
    /// to ten varint bytes; the encoder accepts the cost when
    /// the application sends them.
    pub altitude: i32,
    /// Ground speed in cm/s. Wire form is `uint32` varint.
    pub speed: u32,
    /// Course over ground in degrees × 100, `[0, 36_000)`. Wire
    /// form is `uint32` varint.
    pub course: u32,
}

/// Coordinate scaling factor: `(lat | lon)_i = degrees × 1e7`.
///
/// Public so callers performing custom integration math can use
/// the same constant the codec emits. ≈ 1.1 cm at the equator.
pub const COORD_SCALE: f64 = 10_000_000.0;

/// Speed scaling factor: `speed = m/s × 100` (centimetres per
/// second). The wire form is `cm/s` to keep the magnitude in
/// the single-byte varint range for typical pedestrian /
/// vehicle speeds while still carrying jet-airframe values
/// without overflow.
pub const SPEED_SCALE_CM_PER_S: f64 = 100.0;

/// Course scaling factor: `course = degrees × 100`. Mirrors the
/// upstream Meshtastic firmware's hundredth-degree precision.
pub const COURSE_SCALE_HUNDREDTHS_DEG: f64 = 100.0;

impl Pli {
    /// Convert the wire-format scaled integers into floating-point
    /// `(lat_deg, lon_deg, alt_m, speed_m_s, course_deg)`.
    ///
    /// This is the canonical decode path the entity codec uses to
    /// fold a `Pli` into [`rustgate_core::entity::Position`] /
    /// [`rustgate_core::entity::Velocity`].
    #[must_use]
    pub fn to_position_floats(&self) -> (f64, f64, f64, f64, f64) {
        let lat = f64::from(self.latitude_i) / COORD_SCALE;
        let lon = f64::from(self.longitude_i) / COORD_SCALE;
        let alt = f64::from(self.altitude);
        let speed_m_s = f64::from(self.speed) / SPEED_SCALE_CM_PER_S;
        let course_deg = f64::from(self.course) / COURSE_SCALE_HUNDREDTHS_DEG;
        (lat, lon, alt, speed_m_s, course_deg)
    }

    /// Construct a `Pli` from floating-point inputs, applying the
    /// canonical scaling factors. Inputs are clamped to the i32 /
    /// u32 envelope to avoid panicking on hostile or saturated
    /// values; out-of-envelope values clip rather than wrap.
    ///
    /// Course inputs outside `[0, 360)` are normalised modulo 360
    /// (the wire form is unsigned and the upstream firmware's
    /// magnetometer fusion is free to emit cumulative angles).
    #[must_use]
    pub fn from_position_floats(
        lat_deg: f64,
        lon_deg: f64,
        alt_m: f64,
        speed_m_s: f64,
        course_deg: f64,
    ) -> Self {
        // Course normalisation. NaN propagates to 0 — a NaN on the
        // wire would be silently misinterpreted, so clip at the
        // boundary.
        let course = if course_deg.is_finite() {
            let normalised = course_deg.rem_euclid(360.0);
            clamp_to_u32(normalised * COURSE_SCALE_HUNDREDTHS_DEG)
        } else {
            0
        };
        Self {
            latitude_i: clamp_to_i32(lat_deg * COORD_SCALE),
            longitude_i: clamp_to_i32(lon_deg * COORD_SCALE),
            altitude: clamp_to_i32(alt_m),
            speed: clamp_to_u32(speed_m_s * SPEED_SCALE_CM_PER_S),
            course,
        }
    }
}

/// Geo-chat free-form message body.
///
/// The `to_callsign` field is operator-visible (the recipient name
/// shown on the receiving radio) while `to` is the routing key
/// (typically a UUID / device id). Keeping both lets the receiving
/// radio render a friendly recipient string without a directory
/// lookup; the wire-format names mirror the upstream firmware so
/// cross-codec interop with reference implementations stays one-to-
/// one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GeoChat {
    /// Free-form message body.
    pub message: String,
    /// Routing key (`to` in the upstream schema). Empty on
    /// broadcasts.
    pub to: String,
    /// Operator-visible recipient callsign. Empty on broadcasts.
    pub to_callsign: String,
}

/// Decode a TAKPacket from a length-prefixed-free byte slice.
///
/// The Meshtastic mesh frame already carries the protobuf payload
/// length in its outer header, so this codec consumes a slice that
/// is exactly one TAKPacket on the wire — no length prefix here.
/// Anything beyond [`MAX_PAYLOAD_BYTES`] is rejected as
/// [`MeshtasticError::PayloadTooLarge`] before the parser runs.
pub fn decode_tak_packet(mut bytes: &[u8]) -> Result<TakPacket, MeshtasticError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(MeshtasticError::PayloadTooLarge { bytes: bytes.len() });
    }

    let mut packet = TakPacket::default();
    while bytes.has_remaining() {
        let tag = read_varint(&mut bytes)?;
        match tag {
            TAG_TAK_IS_COMPRESSED => {
                let v = read_varint(&mut bytes)?;
                packet.is_compressed = v != 0;
            }
            TAG_TAK_CONTACT => {
                let inner = read_length_delimited(&mut bytes)?;
                packet.contact = Some(decode_contact(inner)?);
            }
            TAG_TAK_GROUP => {
                let inner = read_length_delimited(&mut bytes)?;
                packet.group = Some(decode_group(inner)?);
            }
            TAG_TAK_STATUS => {
                let inner = read_length_delimited(&mut bytes)?;
                packet.status = Some(decode_status(inner)?);
            }
            TAG_TAK_PLI => {
                let inner = read_length_delimited(&mut bytes)?;
                packet.payload_variant = Some(PayloadVariant::Pli(decode_pli(inner)?));
            }
            TAG_TAK_CHAT => {
                let inner = read_length_delimited(&mut bytes)?;
                packet.payload_variant = Some(PayloadVariant::Chat(decode_chat(inner)?));
            }
            TAG_TAK_DETAIL => {
                let inner = read_length_delimited(&mut bytes)?;
                packet.payload_variant = Some(PayloadVariant::Detail(inner.to_vec()));
            }
            other => skip_unknown_field(&mut bytes, other)?,
        }
    }
    Ok(packet)
}

/// Encode a TAKPacket into a fresh [`Vec<u8>`].
///
/// Returns [`MeshtasticError::PayloadTooLarge`] when the encoded
/// frame would exceed [`MAX_PAYLOAD_BYTES`]. The encoder prunes
/// every empty / default field (see module-level "Field pruning")
/// so a sparse `Pli`-only frame fits comfortably inside the cap.
pub fn encode_tak_packet(packet: &TakPacket) -> Result<Vec<u8>, MeshtasticError> {
    let mut out = Vec::with_capacity(64);
    if packet.is_compressed {
        write_varint(&mut out, TAG_TAK_IS_COMPRESSED);
        write_varint(&mut out, 1);
    }
    if let Some(contact) = &packet.contact
        && !is_contact_empty(contact)
    {
        let inner = encode_contact(contact);
        write_varint(&mut out, TAG_TAK_CONTACT);
        write_length_delimited(&mut out, &inner);
    }
    if let Some(group) = &packet.group
        && !is_group_empty(group)
    {
        let inner = encode_group(group);
        write_varint(&mut out, TAG_TAK_GROUP);
        write_length_delimited(&mut out, &inner);
    }
    if let Some(status) = &packet.status
        && !is_status_empty(status)
    {
        let inner = encode_status(status);
        write_varint(&mut out, TAG_TAK_STATUS);
        write_length_delimited(&mut out, &inner);
    }
    match &packet.payload_variant {
        Some(PayloadVariant::Pli(pli)) => {
            let inner = encode_pli(pli);
            write_varint(&mut out, TAG_TAK_PLI);
            write_length_delimited(&mut out, &inner);
        }
        Some(PayloadVariant::Chat(chat)) => {
            let inner = encode_chat(chat);
            write_varint(&mut out, TAG_TAK_CHAT);
            write_length_delimited(&mut out, &inner);
        }
        Some(PayloadVariant::Detail(detail)) => {
            write_varint(&mut out, TAG_TAK_DETAIL);
            write_length_delimited(&mut out, detail);
        }
        None => {}
    }
    if out.len() > MAX_PAYLOAD_BYTES {
        return Err(MeshtasticError::PayloadTooLarge { bytes: out.len() });
    }
    Ok(out)
}

fn decode_contact(mut bytes: &[u8]) -> Result<Contact, MeshtasticError> {
    let mut contact = Contact::default();
    while bytes.has_remaining() {
        let tag = read_varint(&mut bytes)?;
        match tag {
            TAG_CONTACT_CALLSIGN => {
                let inner = read_length_delimited(&mut bytes)?;
                contact.callsign = bytes_to_utf8(inner)?;
            }
            TAG_CONTACT_DEVICE_CALLSIGN => {
                let inner = read_length_delimited(&mut bytes)?;
                contact.device_callsign = bytes_to_utf8(inner)?;
            }
            other => skip_unknown_field(&mut bytes, other)?,
        }
    }
    Ok(contact)
}

fn decode_group(mut bytes: &[u8]) -> Result<Group, MeshtasticError> {
    let mut group = Group::default();
    while bytes.has_remaining() {
        let tag = read_varint(&mut bytes)?;
        match tag {
            TAG_GROUP_ROLE => {
                let v = read_varint(&mut bytes)?;
                group.role = varint_to_i32(v);
            }
            TAG_GROUP_TEAM => {
                let v = read_varint(&mut bytes)?;
                group.team = varint_to_i32(v);
            }
            other => skip_unknown_field(&mut bytes, other)?,
        }
    }
    Ok(group)
}

fn decode_status(mut bytes: &[u8]) -> Result<Status, MeshtasticError> {
    let mut status = Status::default();
    while bytes.has_remaining() {
        let tag = read_varint(&mut bytes)?;
        match tag {
            TAG_STATUS_BATTERY => {
                let v = read_varint(&mut bytes)?;
                status.battery = u32::try_from(v).unwrap_or(u32::MAX);
            }
            other => skip_unknown_field(&mut bytes, other)?,
        }
    }
    Ok(status)
}

fn decode_pli(mut bytes: &[u8]) -> Result<Pli, MeshtasticError> {
    let mut pli = Pli::default();
    while bytes.has_remaining() {
        let tag = read_varint(&mut bytes)?;
        match tag {
            TAG_PLI_LATITUDE_I => {
                pli.latitude_i = read_sfixed32(&mut bytes)?;
            }
            TAG_PLI_LONGITUDE_I => {
                pli.longitude_i = read_sfixed32(&mut bytes)?;
            }
            TAG_PLI_ALTITUDE => {
                let v = read_varint(&mut bytes)?;
                pli.altitude = varint_to_i32(v);
            }
            TAG_PLI_SPEED => {
                let v = read_varint(&mut bytes)?;
                pli.speed = u32::try_from(v).unwrap_or(u32::MAX);
            }
            TAG_PLI_COURSE => {
                let v = read_varint(&mut bytes)?;
                pli.course = u32::try_from(v).unwrap_or(u32::MAX);
            }
            other => skip_unknown_field(&mut bytes, other)?,
        }
    }
    Ok(pli)
}

fn decode_chat(mut bytes: &[u8]) -> Result<GeoChat, MeshtasticError> {
    let mut chat = GeoChat::default();
    while bytes.has_remaining() {
        let tag = read_varint(&mut bytes)?;
        match tag {
            TAG_CHAT_MESSAGE => {
                let inner = read_length_delimited(&mut bytes)?;
                chat.message = bytes_to_utf8(inner)?;
            }
            TAG_CHAT_TO => {
                let inner = read_length_delimited(&mut bytes)?;
                chat.to = bytes_to_utf8(inner)?;
            }
            TAG_CHAT_TO_CALLSIGN => {
                let inner = read_length_delimited(&mut bytes)?;
                chat.to_callsign = bytes_to_utf8(inner)?;
            }
            other => skip_unknown_field(&mut bytes, other)?,
        }
    }
    Ok(chat)
}

fn is_contact_empty(contact: &Contact) -> bool {
    contact.callsign.is_empty() && contact.device_callsign.is_empty()
}

fn is_group_empty(group: &Group) -> bool {
    group.role == 0 && group.team == 0
}

fn is_status_empty(status: &Status) -> bool {
    status.battery == 0
}

fn encode_contact(contact: &Contact) -> Vec<u8> {
    let mut out = Vec::new();
    if !contact.callsign.is_empty() {
        write_varint(&mut out, TAG_CONTACT_CALLSIGN);
        write_length_delimited(&mut out, contact.callsign.as_bytes());
    }
    if !contact.device_callsign.is_empty() {
        write_varint(&mut out, TAG_CONTACT_DEVICE_CALLSIGN);
        write_length_delimited(&mut out, contact.device_callsign.as_bytes());
    }
    out
}

fn encode_group(group: &Group) -> Vec<u8> {
    let mut out = Vec::new();
    if group.role != 0 {
        write_varint(&mut out, TAG_GROUP_ROLE);
        write_varint(&mut out, i32_to_varint(group.role));
    }
    if group.team != 0 {
        write_varint(&mut out, TAG_GROUP_TEAM);
        write_varint(&mut out, i32_to_varint(group.team));
    }
    out
}

fn encode_status(status: &Status) -> Vec<u8> {
    let mut out = Vec::new();
    if status.battery != 0 {
        write_varint(&mut out, TAG_STATUS_BATTERY);
        write_varint(&mut out, u64::from(status.battery));
    }
    out
}

/// Encode a `Pli` body into its inner length-delimited bytes.
/// Public for the encoder's pruning calculation in [`crate::codec`]
/// where the caller wants to size-budget the inner submessage
/// before deciding whether to emit it.
pub fn encode_pli(pli: &Pli) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    // sfixed32: emit always — the wire form is fixed-width and the
    // zero value is a legitimate equator/prime-meridian fix that
    // some training fixtures need to round-trip.
    write_varint(&mut out, TAG_PLI_LATITUDE_I);
    write_sfixed32(&mut out, pli.latitude_i);
    write_varint(&mut out, TAG_PLI_LONGITUDE_I);
    write_sfixed32(&mut out, pli.longitude_i);
    if pli.altitude != 0 {
        write_varint(&mut out, TAG_PLI_ALTITUDE);
        write_varint(&mut out, i32_to_varint(pli.altitude));
    }
    if pli.speed != 0 {
        write_varint(&mut out, TAG_PLI_SPEED);
        write_varint(&mut out, u64::from(pli.speed));
    }
    if pli.course != 0 {
        write_varint(&mut out, TAG_PLI_COURSE);
        write_varint(&mut out, u64::from(pli.course));
    }
    out
}

fn encode_chat(chat: &GeoChat) -> Vec<u8> {
    let mut out = Vec::with_capacity(chat.message.len() + chat.to.len() + chat.to_callsign.len());
    if !chat.message.is_empty() {
        write_varint(&mut out, TAG_CHAT_MESSAGE);
        write_length_delimited(&mut out, chat.message.as_bytes());
    }
    if !chat.to.is_empty() {
        write_varint(&mut out, TAG_CHAT_TO);
        write_length_delimited(&mut out, chat.to.as_bytes());
    }
    if !chat.to_callsign.is_empty() {
        write_varint(&mut out, TAG_CHAT_TO_CALLSIGN);
        write_length_delimited(&mut out, chat.to_callsign.as_bytes());
    }
    out
}

// --- Wire-format primitives -------------------------------------------------

/// Read a base-128 varint from `bytes`, advancing the cursor. Caps
/// at 10 bytes (the protobuf spec maximum for a 64-bit varint) so
/// hostile input cannot drive the parser into a non-terminating
/// loop.
fn read_varint(bytes: &mut &[u8]) -> Result<u64, MeshtasticError> {
    let mut result: u64 = 0;
    for i in 0..10 {
        if !bytes.has_remaining() {
            return Err(MeshtasticError::TruncatedVarint);
        }
        let b = bytes.get_u8();
        // Each byte contributes 7 bits at position `i * 7`. The
        // protobuf spec caps the output at 64 bits — for `i == 9`
        // only the low bit of the byte is meaningful, but we accept
        // any byte to keep the parser tolerant of forward-compat
        // 128-bit producers (the high bits would be lost on cast).
        result |= (u64::from(b & 0x7F)) << (i * 7);
        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(MeshtasticError::VarintOverflow)
}

/// Write a varint to `out`, using as many 7-bit groups as needed.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.put_u8(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

/// Read a length-delimited segment (varint length followed by bytes)
/// from `bytes`, advancing the cursor past both. Rejects lengths
/// that exceed the transport budget so a malicious sender cannot
/// trigger a multi-megabyte allocation behind the parser.
fn read_length_delimited<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], MeshtasticError> {
    let len = read_varint(bytes)?;
    let len = usize::try_from(len).map_err(|_| MeshtasticError::LengthExceeded {
        bytes: usize::MAX,
        cap: MAX_SKIP_LENGTH,
    })?;
    if len > MAX_SKIP_LENGTH {
        return Err(MeshtasticError::LengthExceeded {
            bytes: len,
            cap: MAX_SKIP_LENGTH,
        });
    }
    if bytes.len() < len {
        return Err(MeshtasticError::Truncated);
    }
    let (head, tail) = bytes.split_at(len);
    *bytes = tail;
    Ok(head)
}

/// Write a length-delimited segment (varint length, then payload).
fn write_length_delimited(out: &mut Vec<u8>, payload: &[u8]) {
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Read a fixed32 little-endian signed integer (`sfixed32` wire
/// form). Two's-complement, no zig-zag.
fn read_sfixed32(bytes: &mut &[u8]) -> Result<i32, MeshtasticError> {
    if bytes.len() < 4 {
        return Err(MeshtasticError::Truncated);
    }
    let raw = bytes.get_u32_le();
    Ok(raw as i32)
}

/// Write a fixed32 little-endian signed integer.
fn write_sfixed32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&(value as u32).to_le_bytes());
}

/// Skip an unknown field, dispatching on the wire type encoded in
/// the low three bits of `tag`. Forward-compatible: a future
/// schema revision that adds new fields stays decodable as long as
/// it uses one of the four standard wire types.
fn skip_unknown_field(bytes: &mut &[u8], tag: u64) -> Result<(), MeshtasticError> {
    let wire_type = tag & 0x07;
    match wire_type {
        0 => {
            // varint
            let _ = read_varint(bytes)?;
        }
        1 => {
            // fixed64
            if bytes.len() < 8 {
                return Err(MeshtasticError::Truncated);
            }
            bytes.advance(8);
        }
        2 => {
            // length-delimited
            let _ = read_length_delimited(bytes)?;
        }
        5 => {
            // fixed32
            if bytes.len() < 4 {
                return Err(MeshtasticError::Truncated);
            }
            bytes.advance(4);
        }
        other => {
            return Err(MeshtasticError::UnknownWireType {
                wire_type: other as u8,
            });
        }
    }
    Ok(())
}

/// Validate a length-delimited byte slice as UTF-8.
fn bytes_to_utf8(bytes: &[u8]) -> Result<String, MeshtasticError> {
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| MeshtasticError::InvalidUtf8 {
            position: e.valid_up_to(),
        })
}

/// Convert a varint-decoded `u64` into an `i32` using the protobuf
/// `int32` rule: the low 32 bits are the two's-complement integer.
/// Forward-compat — if a producer emits an int32 with the high
/// bits sign-extended into 64 bits (legitimate per the spec), the
/// truncation here recovers the intended value.
fn varint_to_i32(v: u64) -> i32 {
    v as i32
}

/// Convert an `i32` to a varint payload using the protobuf `int32`
/// rule. Negative values sign-extend to 10 wire bytes — that is
/// the cost of `int32` (the spec recommends `sint32` for hot
/// negative values, but the upstream Meshtastic schema chose
/// `int32` so we honour the choice).
fn i32_to_varint(v: i32) -> u64 {
    v as i64 as u64
}

fn clamp_to_i32(v: f64) -> i32 {
    if !v.is_finite() {
        return 0;
    }
    let r = v.round();
    if r >= f64::from(i32::MAX) {
        return i32::MAX;
    }
    if r <= f64::from(i32::MIN) {
        return i32::MIN;
    }
    r as i32
}

fn clamp_to_u32(v: f64) -> u32 {
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    let r = v.round();
    if r >= f64::from(u32::MAX) {
        return u32::MAX;
    }
    r as u32
}

impl fmt::Display for PayloadVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pli(_) => f.write_str("pli"),
            Self::Chat(_) => f.write_str("chat"),
            Self::Detail(_) => f.write_str("detail"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::float_cmp, unused_results)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_covers_boundary_widths() {
        // Pin every length boundary: 1-byte (< 128), 2-byte
        // (< 16_384), 3-byte (< 2^21), 5-byte (< 2^35), and 10-byte
        // (full u64). The upstream firmware's varint generator must
        // produce the same bytes for these inputs.
        for v in [0u64, 1, 127, 128, 16_383, 16_384, 1 << 31, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut slice = &buf[..];
            let decoded = read_varint(&mut slice).expect("round-trip");
            assert_eq!(decoded, v, "round-trip mismatch for {v}");
            assert!(slice.is_empty(), "trailing bytes for {v}");
        }
    }

    #[test]
    fn varint_overflow_returns_typed_error() {
        // Eleven 0x80 bytes is past the 10-byte u64 cap. The parser
        // must reject rather than spinning.
        let bytes = [0x80u8; 11];
        let mut slice = &bytes[..];
        let err = read_varint(&mut slice).expect_err("must fail");
        assert!(matches!(err, MeshtasticError::VarintOverflow));
    }

    #[test]
    fn varint_truncated_returns_typed_error() {
        // A continuation byte without a follow-up must surface
        // Truncated rather than a panic.
        let bytes = [0x80u8];
        let mut slice = &bytes[..];
        let err = read_varint(&mut slice).expect_err("must fail");
        assert!(matches!(err, MeshtasticError::TruncatedVarint));
    }

    #[test]
    fn unknown_wire_type_rejects_with_typed_error() {
        // Wire types 3 and 4 are deprecated/unused in the current
        // protobuf spec. The skip path must surface a typed error
        // rather than corrupt the parser's cursor.
        let mut bytes = vec![];
        write_varint(&mut bytes, (99 << 3) | 3); // wire type 3
        let mut slice = &bytes[..];
        let tag = read_varint(&mut slice).unwrap();
        let err = skip_unknown_field(&mut slice, tag).expect_err("must fail");
        match err {
            MeshtasticError::UnknownWireType { wire_type } => assert_eq!(wire_type, 3),
            other => panic!("expected UnknownWireType, got {other:?}"),
        }
    }

    #[test]
    fn pli_round_trips_through_byte_form() {
        let original = Pli {
            latitude_i: 38_889_722,   // ~38.889722°
            longitude_i: -77_008_889, // ~-77.008889°
            altitude: 1234,
            speed: 4500,    // 45 m/s
            course: 18_000, // 180.00°
        };
        let bytes = encode_pli(&original);
        let decoded = decode_pli(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn pli_position_floats_round_trip_within_lsb() {
        let pli = Pli::from_position_floats(38.889_722_2, -77.008_889, 100.0, 25.0, 90.0);
        let (lat, lon, alt, speed, course) = pli.to_position_floats();
        // sfixed32 LSB is 1e-7 deg → ~1.1cm at the equator. Allow
        // 1e-6 deg tolerance.
        assert!((lat - 38.889_722_2).abs() < 1e-6, "lat={lat}");
        assert!((lon - (-77.008_889)).abs() < 1e-6, "lon={lon}");
        assert_eq!(alt, 100.0);
        assert_eq!(speed, 25.0);
        assert_eq!(course, 90.0);
    }

    #[test]
    fn pli_from_floats_clamps_non_finite() {
        // NaN propagates to 0 across every scaled-int field — the
        // encoder must never let a NaN escape into the wire bytes.
        let pli = Pli::from_position_floats(f64::NAN, f64::NAN, f64::NAN, f64::NAN, f64::NAN);
        assert_eq!(pli.latitude_i, 0);
        assert_eq!(pli.longitude_i, 0);
        assert_eq!(pli.altitude, 0);
        assert_eq!(pli.speed, 0);
        assert_eq!(pli.course, 0);
        // Positive infinity also collapses to 0 (clamp_to_i32
        // rejects non-finite inputs as a safety belt) — keep the
        // wire bytes finite at all costs.
        let pli = Pli::from_position_floats(f64::INFINITY, f64::INFINITY, 0.0, 0.0, 0.0);
        assert_eq!(pli.latitude_i, 0);
        assert_eq!(pli.longitude_i, 0);
    }

    #[test]
    fn pli_course_normalisation_handles_overflow() {
        // 720° → 0°, 540° → 180°, -45° → 315°.
        assert_eq!(
            Pli::from_position_floats(0.0, 0.0, 0.0, 0.0, 720.0).course,
            0
        );
        assert_eq!(
            Pli::from_position_floats(0.0, 0.0, 0.0, 0.0, 540.0).course,
            18_000
        );
        assert_eq!(
            Pli::from_position_floats(0.0, 0.0, 0.0, 0.0, -45.0).course,
            31_500
        );
    }

    #[test]
    fn tak_packet_round_trip_with_pli_payload() {
        let original = TakPacket {
            is_compressed: false,
            contact: Some(Contact {
                callsign: "Bravo-1".into(),
                device_callsign: "!a1b2c3d4".into(),
            }),
            group: Some(Group { role: 1, team: 2 }),
            status: Some(Status { battery: 73 }),
            payload_variant: Some(PayloadVariant::Pli(Pli::from_position_floats(
                42.0, -71.0, 100.0, 25.0, 270.0,
            ))),
        };
        let bytes = encode_tak_packet(&original).expect("encode");
        assert!(
            bytes.len() <= MAX_PAYLOAD_BYTES,
            "encoded size {} exceeds cap",
            bytes.len()
        );
        let decoded = decode_tak_packet(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn unknown_field_is_skipped_forward_compat() {
        // Build a frame with a real PLI plus an unknown tag (field
        // number 99, wire type 0). The decoder must skip the
        // unknown field and still surface the PLI.
        let mut frame = Vec::new();
        write_varint(&mut frame, TAG_TAK_IS_COMPRESSED);
        write_varint(&mut frame, 1);
        // Unknown varint field number 99.
        write_varint(&mut frame, 99 << 3);
        write_varint(&mut frame, 42);
        // Real PLI.
        let pli = Pli::from_position_floats(1.0, 2.0, 3.0, 4.0, 5.0);
        let inner = encode_pli(&pli);
        write_varint(&mut frame, TAG_TAK_PLI);
        write_length_delimited(&mut frame, &inner);

        let decoded = decode_tak_packet(&frame).expect("forward-compat skip");
        assert!(decoded.is_compressed);
        assert!(matches!(
            decoded.payload_variant,
            Some(PayloadVariant::Pli(_))
        ));
    }

    #[test]
    fn over_cap_input_is_rejected() {
        // A frame whose total size exceeds 237 bytes must surface
        // PayloadTooLarge before the parser does any work.
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = decode_tak_packet(&oversized).expect_err("must fail");
        assert!(matches!(err, MeshtasticError::PayloadTooLarge { .. }));
    }

    #[test]
    fn invalid_utf8_in_callsign_returns_typed_error() {
        // A callsign field carrying invalid UTF-8 must surface
        // InvalidUtf8 rather than panicking inside the parser.
        let mut inner = Vec::new();
        write_varint(&mut inner, TAG_CONTACT_CALLSIGN);
        write_length_delimited(&mut inner, &[0xFF, 0xFE, 0xFD]);

        let mut frame = Vec::new();
        write_varint(&mut frame, TAG_TAK_CONTACT);
        write_length_delimited(&mut frame, &inner);
        let err = decode_tak_packet(&frame).expect_err("must fail");
        assert!(matches!(err, MeshtasticError::InvalidUtf8 { .. }));
    }
}
