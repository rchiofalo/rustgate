//! MQTT packet framing over TLS streams.
//!
//! Wraps [`mqttbytes`] for codec operations and provides async read/write
//! helpers over [`tokio_rustls`] TLS streams. Supports both MQTT 5.0 and
//! 3.1.1 packet formats, selected per-session based on the CONNECT packet's
//! protocol level byte.

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::MqttError;
use crate::listener::TlsStream;

/// Maximum read buffer size before we consider the client hostile.
const MAX_READ_BUF: usize = 16 * 1024 * 1024; // 16 MiB

/// Protocol version negotiated during CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Async MQTT packet reader/writer over a TLS stream.
///
/// Maintains a read buffer and handles the incremental read loop required
/// by MQTT's variable-length encoding. The protocol level is determined
/// during the initial CONNECT and used for all subsequent packets.
#[derive(Debug)]
pub(crate) struct PacketCodec {
    /// The underlying TLS stream.
    stream: TlsStream,
    /// Read buffer for incremental packet assembly.
    read_buf: BytesMut,
    /// Write buffer for serializing outbound packets.
    write_buf: BytesMut,
    /// Protocol level negotiated at CONNECT time.
    /// `None` until the first CONNECT is parsed.
    pub(crate) protocol: Option<ProtocolLevel>,
    /// Maximum packet size in bytes.
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
    /// For the first packet (before protocol negotiation), this peeks at the
    /// CONNECT packet's protocol level byte to determine v4 vs v5. All
    /// subsequent reads use the negotiated protocol.
    pub(crate) async fn read_packet(&mut self) -> Result<MqttPacket, MqttError> {
        loop {
            // Try to parse a complete packet from the buffer.
            if !self.read_buf.is_empty() {
                match self.try_parse() {
                    Ok(Some(packet)) => return Ok(packet),
                    Ok(None) => {} // Need more data
                    Err(e) => return Err(e),
                }
            }

            // Read more data from the stream.
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

    /// Try to parse a complete packet from the read buffer.
    fn try_parse(&mut self) -> Result<Option<MqttPacket>, MqttError> {
        // If protocol is not yet negotiated, peek at the CONNECT to determine it.
        if self.protocol.is_none() {
            return self.try_parse_connect();
        }

        match self.protocol.unwrap_or(ProtocolLevel::V50) {
            ProtocolLevel::V311 => {
                match mqttbytes::v4::read(&mut self.read_buf, self.max_packet_size) {
                    Ok(packet) => Ok(Some(MqttPacket::V4(packet))),
                    Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
                    Err(e) => Err(MqttError::Malformed(e.to_string())),
                }
            }
            ProtocolLevel::V50 => {
                match mqttbytes::v5::read(&mut self.read_buf, self.max_packet_size) {
                    Ok(packet) => Ok(Some(MqttPacket::V5(Box::new(packet)))),
                    Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
                    Err(e) => Err(MqttError::Malformed(e.to_string())),
                }
            }
        }
    }

    /// Parse the initial CONNECT packet and negotiate the protocol level.
    ///
    /// MQTT CONNECT has a fixed structure: the protocol name "MQTT" followed
    /// by a protocol level byte (4 = 3.1.1, 5 = 5.0). We peek at this byte
    /// to decide which codec to use, then parse the full CONNECT.
    fn try_parse_connect(&mut self) -> Result<Option<MqttPacket>, MqttError> {
        // We need at least 10 bytes to see the protocol level:
        // 1 (fixed header) + 1–4 (remaining length) + 2 (name len) +
        // 4 ("MQTT") + 1 (level). Conservatively require 10.
        if self.read_buf.len() < 10 {
            return Ok(None);
        }

        // Verify this is a CONNECT packet (type 1, upper nibble of byte 0).
        let packet_type = self.read_buf[0] >> 4;
        if packet_type != 1 {
            return Err(MqttError::ConnectExpected);
        }

        // Find the protocol level byte. Skip: fixed header (1) +
        // remaining length (variable 1-4 bytes) + protocol name length (2) +
        // protocol name (4).
        let rl_start = 1;
        let mut rl_len = 0;
        for i in 0..4 {
            if rl_start + i >= self.read_buf.len() {
                return Ok(None); // Need more data
            }
            rl_len += 1;
            if self.read_buf[rl_start + i] & 0x80 == 0 {
                break;
            }
        }

        let level_offset = rl_start + rl_len + 2 + 4; // +2 name len, +4 "MQTT"
        if self.read_buf.len() <= level_offset {
            return Ok(None); // Need more data
        }

        let level = self.read_buf[level_offset];
        let protocol = match level {
            4 => ProtocolLevel::V311,
            5 => ProtocolLevel::V50,
            other => return Err(MqttError::UnsupportedProtocol(other)),
        };

        self.protocol = Some(protocol);

        // Now parse the full CONNECT using the appropriate codec.
        match protocol {
            ProtocolLevel::V311 => {
                match mqttbytes::v4::read(&mut self.read_buf, self.max_packet_size) {
                    Ok(packet) => Ok(Some(MqttPacket::V4(packet))),
                    Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
                    Err(e) => Err(MqttError::Malformed(e.to_string())),
                }
            }
            ProtocolLevel::V50 => {
                match mqttbytes::v5::read(&mut self.read_buf, self.max_packet_size) {
                    Ok(packet) => Ok(Some(MqttPacket::V5(Box::new(packet)))),
                    Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
                    Err(e) => Err(MqttError::Malformed(e.to_string())),
                }
            }
        }
    }

    /// Write an MQTT 3.1.1 packet to the stream.
    pub(crate) async fn write_v4(
        &mut self,
        packet: &mqttbytes::v4::Packet,
    ) -> Result<(), MqttError> {
        self.write_buf.clear();
        write_v4_packet(packet, &mut self.write_buf)?;
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
        write_v5_packet(packet, &mut self.write_buf)?;
        self.stream
            .write_all(&self.write_buf)
            .await
            .map_err(MqttError::Io)?;
        self.stream.flush().await.map_err(MqttError::Io)?;
        Ok(())
    }

    /// Write a protocol-appropriate packet based on the negotiated version.
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

    /// Write a PINGRESP.
    pub(crate) async fn write_pingresp(&mut self) -> Result<(), MqttError> {
        match self.protocol.unwrap_or(ProtocolLevel::V50) {
            ProtocolLevel::V311 => self.write_v4(&mqttbytes::v4::Packet::PingResp).await,
            ProtocolLevel::V50 => self.write_v5(&mqttbytes::v5::Packet::PingResp).await,
        }
    }
}

/// Serialize a v4 packet into a buffer.
fn write_v4_packet(packet: &mqttbytes::v4::Packet, buf: &mut BytesMut) -> Result<(), MqttError> {
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
fn write_v5_packet(packet: &mqttbytes::v5::Packet, buf: &mut BytesMut) -> Result<(), MqttError> {
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
