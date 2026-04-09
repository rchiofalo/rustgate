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
