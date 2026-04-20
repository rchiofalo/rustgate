// Copyright © 2026 Roberto Chiofalo.

//! MQTT packet framing over TLS streams.
//!
//! Wraps [`mqttbytes`] for codec operations and provides async read/write
//! helpers over [`tokio_rustls`] TLS streams. Supports both MQTT 5.0 and
//! 3.1.1 packet formats, selected per-session based on the CONNECT packet's
//! protocol level byte.
//!
//! The codec is split into [`PacketReader`] and [`PacketWriter`] halves via
//! [`tokio::io::split`] so the read and write loops can run concurrently
//! without sharing the underlying TLS stream.

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::error::MqttError;
use crate::listener::TlsStream;

/// Maximum read buffer size before we consider the client hostile.
const MAX_READ_BUF: usize = 16 * 1024 * 1024; // 16 MiB

/// Threshold below which we shrink the read buffer after a large packet.
/// If the buffer grew past this point but is now mostly consumed, reclaim
/// the memory so long-lived sessions don't hold 16 MiB forever.
const READ_BUF_SHRINK_THRESHOLD: usize = 64 * 1024; // 64 KiB

/// Protocol version negotiated during CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ProtocolLevel {
    /// MQTT 3.1.1 (protocol level 4).
    V311,
    /// MQTT 5.0 (protocol level 5).
    V50,
}

/// A decoded MQTT packet, version-tagged.
#[derive(Debug)]
pub(crate) enum MqttPacket {
    /// MQTT 3.1.1 packet.
    V4(mqttbytes::v4::Packet),
    /// MQTT 5.0 packet (boxed to avoid 384-byte stack enum).
    V5(Box<mqttbytes::v5::Packet>),
}

/// Combined codec used during the CONNECT handshake, before the stream is
/// split into independent read/write halves.
///
/// After the handshake, call [`into_split`](PacketCodec::into_split) to
/// obtain a [`PacketReader`] and [`PacketWriter`] for concurrent operation.
#[derive(Debug)]
pub(crate) struct PacketCodec {
    stream: TlsStream,
    read_buf: BytesMut,
    write_buf: BytesMut,
    pub(crate) protocol: Option<ProtocolLevel>,
    max_packet_size: usize,
}

impl PacketCodec {
    /// Create a new codec wrapping the given TLS stream.
    pub(crate) fn new(stream: TlsStream, max_packet_size: usize) -> Self {
        Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            write_buf: BytesMut::with_capacity(4096),
            protocol: None,
            max_packet_size,
        }
    }

    /// Read the next MQTT packet from the stream.
    ///
    /// Used only during the CONNECT handshake before the stream is split.
    pub(crate) async fn read_packet(&mut self) -> Result<MqttPacket, MqttError> {
        loop {
            if !self.read_buf.is_empty() {
                match try_parse(&mut self.read_buf, &mut self.protocol, self.max_packet_size) {
                    Ok(Some(packet)) => return Ok(packet),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            }

            if self.read_buf.len() >= MAX_READ_BUF {
                return Err(MqttError::PacketTooLarge {
                    size: self.read_buf.len(),
                    max: MAX_READ_BUF,
                });
            }

            let n = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(MqttError::Io)?;

            if n == 0 {
                return Err(MqttError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )));
            }
        }
    }

    /// Write an MQTT 3.1.1 packet to the stream.
    pub(crate) async fn write_v4(
        &mut self,
        packet: &mqttbytes::v4::Packet,
    ) -> Result<(), MqttError> {
        self.write_buf.clear();
        write_v4_to_buf(packet, &mut self.write_buf)?;
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(MqttError::Io)?;
        self.stream.flush().await.map_err(MqttError::Io)?;
        Ok(())
    }

    /// Write an MQTT 5.0 packet to the stream.
    pub(crate) async fn write_v5(
        &mut self,
        packet: &mqttbytes::v5::Packet,
    ) -> Result<(), MqttError> {
        self.write_buf.clear();
        write_v5_to_buf(packet, &mut self.write_buf)?;
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(MqttError::Io)?;
        self.stream.flush().await.map_err(MqttError::Io)?;
        Ok(())
    }

    /// Write a v4 CONNACK with a return code.
    pub(crate) async fn write_connack_v4(
        &mut self,
        code: mqttbytes::v4::ConnectReturnCode,
    ) -> Result<(), MqttError> {
        let connack = mqttbytes::v4::ConnAck {
            session_present: false,
            code,
        };
        self.write_v4(&mqttbytes::v4::Packet::ConnAck(connack))
            .await
    }

    /// Write a v5 CONNACK with a reason code.
    ///
    /// Uses `Some(ConnAckProperties::new())` instead of `None` because
    /// mqttbytes 0.6 has a bug: `ConnAck::write` omits the required
    /// properties length byte when `properties` is `None`, causing the
    /// reader to choke on the incomplete packet.
    pub(crate) async fn write_connack_v5(
        &mut self,
        code: mqttbytes::v5::ConnectReturnCode,
    ) -> Result<(), MqttError> {
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code,
            properties: Some(mqttbytes::v5::ConnAckProperties::new()),
        };
        self.write_v5(&mqttbytes::v5::Packet::ConnAck(connack))
            .await
    }

    /// Split the codec into independent read and write halves.
    ///
    /// The remaining read buffer and protocol level are carried over to the
    /// reader. The writer gets a fresh write buffer.
    pub(crate) fn into_split(self) -> (PacketReader, PacketWriter) {
        let (read_half, write_half) = tokio::io::split(self.stream);
        let protocol = self.protocol.unwrap_or(ProtocolLevel::V50);
        (
            PacketReader {
                stream: read_half,
                read_buf: self.read_buf,
                protocol,
                max_packet_size: self.max_packet_size,
            },
            PacketWriter {
                stream: write_half,
                write_buf: self.write_buf,
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Read half
// ---------------------------------------------------------------------------

/// Read half of the MQTT codec. Owns the TLS read stream and read buffer.
#[derive(Debug)]
pub(crate) struct PacketReader {
    stream: ReadHalf<TlsStream>,
    read_buf: BytesMut,
    protocol: ProtocolLevel,
    max_packet_size: usize,
}

impl PacketReader {
    /// Read the next MQTT packet from the stream.
    pub(crate) async fn read_packet(&mut self) -> Result<MqttPacket, MqttError> {
        loop {
            if !self.read_buf.is_empty() {
                let mut protocol = Some(self.protocol);
                match try_parse(&mut self.read_buf, &mut protocol, self.max_packet_size) {
                    Ok(Some(packet)) => {
                        self.maybe_shrink_buf();
                        return Ok(packet);
                    }
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            }

            if self.read_buf.len() >= MAX_READ_BUF {
                return Err(MqttError::PacketTooLarge {
                    size: self.read_buf.len(),
                    max: MAX_READ_BUF,
                });
            }

            let n = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(MqttError::Io)?;

            if n == 0 {
                return Err(MqttError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                )));
            }
        }
    }

    /// Shrink the read buffer if it grew large but is now mostly consumed.
    fn maybe_shrink_buf(&mut self) {
        if self.read_buf.capacity() > READ_BUF_SHRINK_THRESHOLD
            && self.read_buf.len() < READ_BUF_SHRINK_THRESHOLD / 4
        {
            let remaining = self.read_buf.split();
            self.read_buf = BytesMut::with_capacity(4096);
            self.read_buf.extend_from_slice(&remaining);
        }
    }
}

// ---------------------------------------------------------------------------
// Write half
// ---------------------------------------------------------------------------

/// Write half of the MQTT codec. Owns the TLS write stream and write buffer.
#[derive(Debug)]
pub(crate) struct PacketWriter {
    stream: WriteHalf<TlsStream>,
    write_buf: BytesMut,
}

impl PacketWriter {
    /// Write an MQTT 3.1.1 packet to the stream.
    pub(crate) async fn write_v4(
        &mut self,
        packet: &mqttbytes::v4::Packet,
    ) -> Result<(), MqttError> {
        self.write_buf.clear();
        write_v4_to_buf(packet, &mut self.write_buf)?;
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(MqttError::Io)?;
        self.stream.flush().await.map_err(MqttError::Io)?;
        Ok(())
    }

    /// Write an MQTT 5.0 packet to the stream.
    pub(crate) async fn write_v5(
        &mut self,
        packet: &mqttbytes::v5::Packet,
    ) -> Result<(), MqttError> {
        self.write_buf.clear();
        write_v5_to_buf(packet, &mut self.write_buf)?;
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(MqttError::Io)?;
        self.stream.flush().await.map_err(MqttError::Io)?;
        Ok(())
    }

    /// Write pre-serialized bytes directly to the TLS stream.
    ///
    /// Used by the write loop to send response packets that were serialized
    /// by the read loop (PUBACK, SUBACK, PINGRESP, etc.).
    pub(crate) async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), MqttError> {
        self.stream.write_all(bytes).await.map_err(MqttError::Io)?;
        self.stream.flush().await.map_err(MqttError::Io)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared parsing logic
// ---------------------------------------------------------------------------

/// Try to parse a complete packet from the read buffer.
///
/// When `protocol` is `None`, peeks at the CONNECT packet to negotiate the
/// protocol level (writing it back into the `Option`). Subsequent calls with
/// `Some(level)` use the negotiated codec directly.
fn try_parse(
    buf: &mut BytesMut,
    protocol: &mut Option<ProtocolLevel>,
    max_packet_size: usize,
) -> Result<Option<MqttPacket>, MqttError> {
    if protocol.is_none() {
        return try_parse_connect(buf, protocol, max_packet_size);
    }

    match protocol.unwrap_or(ProtocolLevel::V50) {
        ProtocolLevel::V311 => match mqttbytes::v4::read(buf, max_packet_size) {
            Ok(packet) => Ok(Some(MqttPacket::V4(packet))),
            Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
            Err(e) => Err(MqttError::Malformed(e.to_string())),
        },
        ProtocolLevel::V50 => match mqttbytes::v5::read(buf, max_packet_size) {
            Ok(packet) => Ok(Some(MqttPacket::V5(Box::new(packet)))),
            Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
            Err(e) => Err(MqttError::Malformed(e.to_string())),
        },
    }
}

/// Parse the initial CONNECT packet and negotiate the protocol level.
fn try_parse_connect(
    buf: &mut BytesMut,
    protocol: &mut Option<ProtocolLevel>,
    max_packet_size: usize,
) -> Result<Option<MqttPacket>, MqttError> {
    // We need at least 10 bytes to see the protocol level:
    // 1 (fixed header) + 1–4 (remaining length) + 2 (name len) +
    // 4 ("MQTT") + 1 (level). Conservatively require 10.
    if buf.len() < 10 {
        return Ok(None);
    }

    // Verify this is a CONNECT packet (type 1, upper nibble of byte 0).
    let packet_type = buf[0] >> 4;
    if packet_type != 1 {
        return Err(MqttError::ConnectExpected);
    }

    // Find the protocol level byte. Skip: fixed header (1) +
    // remaining length (variable 1-4 bytes) + protocol name length (2) +
    // protocol name (4).
    let rl_start = 1;
    let mut rl_len = 0;
    for i in 0..4 {
        if rl_start + i >= buf.len() {
            return Ok(None);
        }
        rl_len += 1;
        if buf[rl_start + i] & 0x80 == 0 {
            break;
        }
    }

    let level_offset = rl_start + rl_len + 2 + 4; // +2 name len, +4 "MQTT"
    if buf.len() <= level_offset {
        return Ok(None);
    }

    let level = buf[level_offset];
    let negotiated = match level {
        4 => ProtocolLevel::V311,
        5 => ProtocolLevel::V50,
        other => return Err(MqttError::UnsupportedProtocol(other)),
    };

    *protocol = Some(negotiated);

    match negotiated {
        ProtocolLevel::V311 => match mqttbytes::v4::read(buf, max_packet_size) {
            Ok(packet) => Ok(Some(MqttPacket::V4(packet))),
            Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
            Err(e) => Err(MqttError::Malformed(e.to_string())),
        },
        ProtocolLevel::V50 => match mqttbytes::v5::read(buf, max_packet_size) {
            Ok(packet) => Ok(Some(MqttPacket::V5(Box::new(packet)))),
            Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
            Err(e) => Err(MqttError::Malformed(e.to_string())),
        },
    }
}

// ---------------------------------------------------------------------------
// Packet serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a v4 packet into a buffer.
pub(crate) fn write_v4_to_buf(
    packet: &mqttbytes::v4::Packet,
    buf: &mut BytesMut,
) -> Result<(), MqttError> {
    use mqttbytes::v4::Packet;
    let _ = match packet {
        Packet::ConnAck(p) => p.write(buf),
        Packet::Publish(p) => p.write(buf),
        Packet::PubAck(p) => p.write(buf),
        Packet::SubAck(p) => p.write(buf),
        Packet::UnsubAck(p) => p.write(buf),
        Packet::PingResp => mqttbytes::v4::PingResp.write(buf),
        Packet::Disconnect => mqttbytes::v4::Disconnect.write(buf),
        _ => return Ok(()), // Server doesn't send other packet types
    }
    .map_err(|e| MqttError::Malformed(format!("write error: {e}")))?;
    Ok(())
}

/// Serialize a v5 packet into a buffer.
pub(crate) fn write_v5_to_buf(
    packet: &mqttbytes::v5::Packet,
    buf: &mut BytesMut,
) -> Result<(), MqttError> {
    use mqttbytes::v5::Packet;
    let _ = match packet {
        Packet::ConnAck(p) => p.write(buf),
        Packet::Publish(p) => p.write(buf),
        Packet::PubAck(p) => p.write(buf),
        Packet::SubAck(p) => p.write(buf),
        Packet::UnsubAck(p) => p.write(buf),
        Packet::PingResp => mqttbytes::v5::PingResp.write(buf),
        Packet::Disconnect(p) => p.write(buf),
        _ => return Ok(()), // Server doesn't send other packet types
    }
    .map_err(|e| MqttError::Malformed(format!("write error: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, unused_results)]
mod tests {
    //! Unit tests for the pure codec paths (protocol negotiation, framing,
    //! serialization). The I/O-wrapping types (`PacketCodec`, `PacketReader`,
    //! `PacketWriter`) hold a `TlsStream` and are covered by the integration
    //! tests in `tests/mqtt_integration.rs`; the tests here target the
    //! byte-level logic that doesn't need a live TLS stream to exercise.

    use mqttbytes::QoS;

    use super::*;

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /// Build on-the-wire bytes for a minimal v3.1.1 CONNECT.
    fn v4_connect_bytes(client_id: &str) -> BytesMut {
        let connect = mqttbytes::v4::Connect::new(client_id);
        let mut buf = BytesMut::with_capacity(64);
        connect.write(&mut buf).expect("write v4 connect");
        buf
    }

    /// Build on-the-wire bytes for a minimal v5 CONNECT.
    fn v5_connect_bytes(client_id: &str) -> BytesMut {
        let connect = mqttbytes::v5::Connect::new(client_id);
        let mut buf = BytesMut::with_capacity(64);
        connect.write(&mut buf).expect("write v5 connect");
        buf
    }

    // -----------------------------------------------------------------
    // Protocol negotiation (try_parse_connect)
    // -----------------------------------------------------------------

    #[test]
    fn connect_returns_none_for_buffer_shorter_than_ten_bytes() {
        // The parser needs at least 10 bytes to peek at the protocol level;
        // anything shorter must be an incremental "read more" signal, not
        // an error — otherwise we'd reject clients whose CONNECT bytes
        // arrive in multiple TCP reads (the common case on slow links).
        let mut buf = BytesMut::from(&b"\x10\x0c\x00\x04MQ"[..]);
        let mut protocol = None;
        let r = try_parse_connect(&mut buf, &mut protocol, 16 * 1024).expect("ok");
        assert!(r.is_none());
        assert!(
            protocol.is_none(),
            "must not commit to a protocol level yet"
        );
    }

    #[test]
    fn connect_returns_none_when_level_byte_is_beyond_buffer() {
        // Pass the initial 10-byte gate, but use a 3-byte remaining-length
        // encoding so `level_offset = 1 + rl_len + 2 + 4 = 10` lands
        // exactly at buffer end — the level byte has not yet arrived.
        // The parser must return `Ok(None)` ("need more bytes") instead of
        // committing to a protocol level or reading past the buffer end.
        //
        // Bytes: `\x10` (CONNECT), `\x80\x80\x01` (continuation-flagged
        // remaining length), six filler bytes for the partial variable
        // header = 10 bytes total.
        let mut buf = BytesMut::from(&b"\x10\x80\x80\x01XXXXXX"[..]);
        assert_eq!(buf.len(), 10, "test relies on exact 10-byte boundary");
        let mut protocol = None;
        let r = try_parse_connect(&mut buf, &mut protocol, 16 * 1024).expect("ok");
        assert!(
            r.is_none(),
            "must signal need-more-bytes, not commit a level"
        );
        assert!(protocol.is_none());
    }

    #[test]
    fn connect_rejects_non_connect_packet_type() {
        // First byte 0x30 == PUBLISH (type 3 in upper nibble). Any packet
        // other than CONNECT at handshake time is a protocol violation —
        // the server must abort immediately rather than wait for more
        // bytes that would never reinterpret this as a CONNECT.
        let mut buf = BytesMut::from(&b"\x30\x0c\x00\x04MQTT\x04\x02\x00\x00"[..]);
        let mut protocol = None;
        let err = try_parse_connect(&mut buf, &mut protocol, 16 * 1024).unwrap_err();
        assert!(matches!(err, MqttError::ConnectExpected));
        assert!(protocol.is_none(), "protocol must stay unset on rejection");
    }

    #[test]
    fn connect_rejects_unsupported_protocol_level() {
        // Construct a syntactically valid CONNECT frame whose protocol
        // level is 3 (legacy MQTT 3.1 / "MQIsdp"). The parser only scans
        // for the level byte at a known offset; surfacing the raw value
        // in the error helps operators diagnose legacy clients.
        let mut buf = BytesMut::from(&b"\x10\x0c\x00\x04MQTT\x03\x02\x00\x00"[..]);
        let mut protocol = None;
        let err = try_parse_connect(&mut buf, &mut protocol, 16 * 1024).unwrap_err();
        match err {
            MqttError::UnsupportedProtocol(level) => assert_eq!(level, 3),
            other => panic!("expected UnsupportedProtocol(3), got {other:?}"),
        }
    }

    #[test]
    fn connect_level_4_negotiates_v311() {
        let mut buf = v4_connect_bytes("client-a");
        let mut protocol = None;
        let packet = try_parse_connect(&mut buf, &mut protocol, 16 * 1024)
            .expect("ok")
            .expect("packet decoded");
        assert_eq!(protocol, Some(ProtocolLevel::V311));
        assert!(matches!(
            packet,
            MqttPacket::V4(mqttbytes::v4::Packet::Connect(_))
        ));
        assert!(buf.is_empty(), "full packet was consumed");
    }

    #[test]
    fn connect_level_5_negotiates_v50() {
        let mut buf = v5_connect_bytes("client-b");
        let mut protocol = None;
        let packet = try_parse_connect(&mut buf, &mut protocol, 16 * 1024)
            .expect("ok")
            .expect("packet decoded");
        assert_eq!(protocol, Some(ProtocolLevel::V50));
        match packet {
            MqttPacket::V5(boxed) => assert!(matches!(*boxed, mqttbytes::v5::Packet::Connect(_))),
            MqttPacket::V4(_) => panic!("expected v5 packet"),
        }
        assert!(buf.is_empty(), "full packet was consumed");
    }

    // -----------------------------------------------------------------
    // Top-level dispatcher (try_parse)
    // -----------------------------------------------------------------

    #[test]
    fn try_parse_with_v311_protocol_decodes_without_renegotiation() {
        // Once the handshake has chosen V311, subsequent packets must be
        // decoded via the v4 codec — not routed back through the CONNECT
        // negotiator. A PUBACK is a good signal because it exists in
        // both versions but has different wire formats for reason codes,
        // so picking the wrong codec would surface as Malformed.
        let puback = mqttbytes::v4::PubAck::new(42);
        let mut buf = BytesMut::with_capacity(8);
        puback.write(&mut buf).expect("encode puback");
        let mut protocol = Some(ProtocolLevel::V311);
        let packet = try_parse(&mut buf, &mut protocol, 16 * 1024)
            .expect("ok")
            .expect("decoded");
        assert!(matches!(
            packet,
            MqttPacket::V4(mqttbytes::v4::Packet::PubAck(pa)) if pa.pkid == 42,
        ));
    }

    #[test]
    fn try_parse_with_v50_protocol_decodes_without_renegotiation() {
        // Symmetric coverage for the v5 dispatch arm — a regression that
        // routed post-handshake v5 traffic through the CONNECT negotiator
        // would fail every non-CONNECT packet type on a v5 session.
        let puback = mqttbytes::v5::PubAck::new(99);
        let mut buf = BytesMut::with_capacity(16);
        puback.write(&mut buf).expect("encode v5 puback");
        let mut protocol = Some(ProtocolLevel::V50);
        let packet = try_parse(&mut buf, &mut protocol, 16 * 1024)
            .expect("ok")
            .expect("decoded");
        match packet {
            MqttPacket::V5(boxed) => assert!(matches!(
                *boxed,
                mqttbytes::v5::Packet::PubAck(pa) if pa.pkid == 99,
            )),
            MqttPacket::V4(_) => panic!("expected v5 decode"),
        }
    }

    #[test]
    fn try_parse_insufficient_bytes_returns_none() {
        // The codec owns buffer refill; a partial frame MUST NOT error
        // — it must signal "read more" so the outer loop can fill the
        // buffer on the next tokio read.
        let mut buf = BytesMut::from(&b"\x40"[..]); // PUBACK type byte alone
        let mut protocol = Some(ProtocolLevel::V311);
        let r = try_parse(&mut buf, &mut protocol, 16 * 1024).expect("ok");
        assert!(r.is_none());
    }

    #[test]
    fn try_parse_malformed_frame_returns_malformed_error() {
        // SUBSCRIBE with rem_len=0 — mqttbytes emits PayloadRequired;
        // we remap all non-insufficient errors to `Malformed(String)` so
        // the session layer has a single fatal-parse path to handle.
        let mut buf = BytesMut::from(&b"\x82\x00"[..]);
        let mut protocol = Some(ProtocolLevel::V311);
        let err = try_parse(&mut buf, &mut protocol, 16 * 1024).unwrap_err();
        assert!(matches!(err, MqttError::Malformed(_)));
    }

    #[test]
    fn try_parse_none_protocol_delegates_to_connect_negotiator() {
        // With protocol=None, try_parse must route to try_parse_connect
        // — the fact that this is a PUBLISH must surface as
        // `ConnectExpected`, not as a parse error on the PUBLISH itself.
        let mut buf = BytesMut::from(&b"\x30\x0c\x00\x04MQTT\x04\x02\x00\x00"[..]);
        let mut protocol: Option<ProtocolLevel> = None;
        let err = try_parse(&mut buf, &mut protocol, 16 * 1024).unwrap_err();
        assert!(matches!(err, MqttError::ConnectExpected));
    }

    // -----------------------------------------------------------------
    // Serialization (write_v4_to_buf / write_v5_to_buf)
    // -----------------------------------------------------------------

    #[test]
    fn write_v4_connack_roundtrips_through_parser() {
        let connack = mqttbytes::v4::ConnAck {
            session_present: false,
            code: mqttbytes::v4::ConnectReturnCode::Success,
        };
        let mut buf = BytesMut::with_capacity(16);
        write_v4_to_buf(&mqttbytes::v4::Packet::ConnAck(connack), &mut buf).expect("serialize");
        assert!(!buf.is_empty());

        let decoded = mqttbytes::v4::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v4::Packet::ConnAck(a) => {
                assert_eq!(a.code, mqttbytes::v4::ConnectReturnCode::Success);
                assert!(!a.session_present);
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn write_v4_publish_roundtrips() {
        let publish = mqttbytes::v4::Publish::new("a/b", QoS::AtMostOnce, b"payload".to_vec());
        let mut buf = BytesMut::with_capacity(64);
        write_v4_to_buf(&mqttbytes::v4::Packet::Publish(publish), &mut buf).expect("serialize");

        let decoded = mqttbytes::v4::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v4::Packet::Publish(p) => {
                assert_eq!(p.topic, "a/b");
                assert_eq!(&p.payload[..], b"payload");
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    #[test]
    fn write_v4_server_only_packets_are_silent_noop() {
        // The server never encodes Connect, Subscribe, or PingReq — the
        // `_ => Ok(())` arm in write_v4_to_buf silently skips them. This
        // is deliberate: flipping it to panic-on-unknown would make every
        // future packet-type addition a potential DoS vector. Pinning
        // the contract here keeps a future refactor honest.
        let cases: [mqttbytes::v4::Packet; 3] = [
            mqttbytes::v4::Packet::Connect(mqttbytes::v4::Connect::new("c")),
            mqttbytes::v4::Packet::Subscribe(mqttbytes::v4::Subscribe::new("t", QoS::AtMostOnce)),
            mqttbytes::v4::Packet::PingReq,
        ];
        for pkt in cases {
            let mut buf = BytesMut::with_capacity(16);
            write_v4_to_buf(&pkt, &mut buf).expect("noop");
            assert!(
                buf.is_empty(),
                "server-only packet {pkt:?} must not emit bytes",
            );
        }
    }

    #[test]
    fn write_v5_connack_roundtrips_through_parser() {
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some(mqttbytes::v5::ConnAckProperties::new()),
        };
        let mut buf = BytesMut::with_capacity(16);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");
        assert!(!buf.is_empty());

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        assert!(matches!(
            decoded,
            mqttbytes::v5::Packet::ConnAck(a) if matches!(a.code, mqttbytes::v5::ConnectReturnCode::Success),
        ));
    }

    #[test]
    fn write_v5_disconnect_produces_bytes() {
        // Distinct from v4: the server actively sends v5 Disconnect with
        // a reason code. A regression in the `Disconnect(p) => p.write()`
        // arm would silently drop every server-initiated disconnect,
        // indistinguishable from "client reset the TCP" to the client.
        let disconnect = mqttbytes::v5::Disconnect::new();
        let mut buf = BytesMut::with_capacity(16);
        write_v5_to_buf(&mqttbytes::v5::Packet::Disconnect(disconnect), &mut buf)
            .expect("serialize");
        assert!(!buf.is_empty());
        // First byte is the fixed header: upper nibble is packet type.
        // DISCONNECT is type 14 (0xE0 >> 4 == 0x0E).
        assert_eq!(buf[0] >> 4, 0x0E);
    }
}
