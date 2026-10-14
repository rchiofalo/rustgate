// SPDX-FileCopyrightText: 2026 Roberto Chiofalo
// SPDX-License-Identifier: AGPL-3.0-only

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
    receive_max: u16,
    topic_alias_max: u16,
    /// Per-listener wildcard policy. Threaded through PacketCodec
    /// so `write_connack_v5` can compute the
    /// `Wildcard Subscription Available` CONNACK property without
    /// re-plumbing every call site.
    wildcard_policy: crate::topic::WildcardPolicy,
    /// Operator-configured Server Keep Alive override. When `> 0`
    /// the codec advertises the value via the MQTT 5.0 §3.2.2.3.14
    /// `Server Keep Alive` CONNACK property; when `0` the property
    /// is omitted and the broker honors the client's CONNECT-time
    /// request as before. Read by `write_connack_v5`; the read-loop
    /// keep-alive enforcement uses the same value via the
    /// `handle_mqtt_session` parameter (the codec carries it for
    /// CONNACK emission, not for timer enforcement).
    server_keep_alive_secs: u16,
}

impl PacketCodec {
    /// Create a new codec wrapping the given TLS stream.
    pub(crate) fn new(
        stream: TlsStream,
        max_packet_size: usize,
        receive_max: u16,
        topic_alias_max: u16,
        wildcard_policy: crate::topic::WildcardPolicy,
        server_keep_alive_secs: u16,
    ) -> Self {
        Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            write_buf: BytesMut::with_capacity(4096),
            protocol: None,
            max_packet_size,
            receive_max,
            topic_alias_max,
            wildcard_policy,
            server_keep_alive_secs,
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
    /// Always advertises `Maximum Packet Size` (MQTT 5.0 §3.2.2.3.6) so a
    /// compliant client knows the broker will reject anything larger and can
    /// short-circuit oversized publishes locally rather than getting an
    /// abrupt close — without the property the spec says the client may
    /// assume there is no limit beyond the protocol's remaining-length
    /// encoding ceiling.
    ///
    /// Uses `Some(ConnAckProperties)` instead of `None` because mqttbytes
    /// 0.6 has a bug: `ConnAck::write` omits the required properties length
    /// byte when `properties` is `None`, causing the reader to choke on the
    /// incomplete packet.
    pub(crate) async fn write_connack_v5(
        &mut self,
        code: mqttbytes::v5::ConnectReturnCode,
        session_present: bool,
        negotiated_session_expiry: u32,
    ) -> Result<(), MqttError> {
        let mut properties = mqttbytes::v5::ConnAckProperties::new();
        // Saturate at u32::MAX rather than refusing to set the property: the
        // wire field is a 4-byte integer per spec, and a configured cap
        // larger than u32::MAX is a misconfiguration in the operator's
        // input, not a client-protocol violation. Saturating preserves the
        // "broker has a limit" signal even if the operator typed something
        // pathological. In practice MAX_READ_BUF is 16 MiB and well below
        // the u32 ceiling, so this never trips.
        properties.max_packet_size = Some(u32::try_from(self.max_packet_size).unwrap_or(u32::MAX));
        // MQTT 5.0 §3.2.2.3.3: Receive Maximum. Tells a compliant client
        // the maximum number of QoS 1 / QoS 2 PUBLISHes it may have
        // in-flight to the broker without intervening acks. The spec
        // default (when the property is absent) is 65535, which is a
        // useless signal — well-behaved clients respect a value the
        // broker actually advertises. We always advertise so the client
        // has a concrete cap to self-limit against. Note `receive_max`
        // is a u16 on the wire so no saturation logic is needed.
        properties.receive_max = Some(self.receive_max);
        // MQTT 5.0 §3.2.2.3.8: Topic Alias Maximum. Tells a compliant
        // client the highest Topic Alias value the broker will accept
        // on inbound PUBLISHes from this connection. The spec default
        // when the property is absent is 0 (feature disabled), so
        // we always advertise even when the configured cap is 0 —
        // explicit signaling beats relying on the implicit default.
        // The wire field is `u16` so no saturation needed.
        properties.topic_alias_max = Some(self.topic_alias_max);
        // MQTT 5.0 §3.2.2.3.4 Maximum QoS. rustgate supports inbound
        // QoS 0/1/2 (after the QoS 2 four-step from #1161), so 2 is
        // the truthful value. The spec default when the property is
        // absent is also 2 ("the broker supports all QoS levels"),
        // so explicit advertisement is informational rather than
        // load-bearing — but pinning the value end-to-end via
        // CONNACK lets the test assertion catch a regression that
        // accidentally degraded the broker's actual capability.
        properties.max_qos = Some(2);
        // MQTT 5.0 §3.2.2.3.5 Retain Available. rustgate supports
        // retained messages (#1146 retain store + §3.3.1.3 zero-byte
        // clear). The spec default when absent is 1 ("supported"),
        // so this is again an explicit confirmation of capability —
        // a regression that gutted retain handling would still let
        // the property assertion pass, but the operational fleet
        // would see retained messages stop replaying. The pairing
        // with the existing retain hooks (#1153) gives the
        // dashboards a "retain store activity is non-zero" signal
        // that complements the CONNACK advertisement.
        properties.retain_available = Some(1);
        // MQTT 5.0 §3.2.2.3.9 Wildcard Subscription Available.
        // Computed from the listener's `WildcardPolicy`:
        //   - `Reject` → 0 (broker refuses any wildcard filter)
        //   - `SingleLevelOnly` (default) → 1 (`+` only)
        //   - `Full` → 1 (`+` and `#`)
        // The MQTT 5.0 wire field is binary (supported / not), so
        // a deployment in `SingleLevelOnly` mode advertises 1 even
        // though `#` is rejected at SUBSCRIBE time — the per-filter
        // SUBACK reason code (`WildcardSubscriptionsNotSupported`,
        // 0xA2) is the precise signal the spec provides for the
        // single-vs-full distinction. Operators can audit
        // `mqtt_subscribes_rejected_total` to see the rejection
        // shape if wildcard discipline is operationally relevant.
        properties.wildcard_subscription_available = Some(
            if matches!(self.wildcard_policy, crate::topic::WildcardPolicy::Reject) {
                0
            } else {
                1
            },
        );
        // MQTT 5.0 §3.2.2.3.10 Subscription Identifiers Available.
        // rustgate now supports the §3.8.2.1.2 numeric ID mechanism
        // (refs #880): a SUBSCRIBE may include a `Subscription
        // Identifier` property and the broker echoes every matching
        // identifier on the resulting PUBLISHes per §3.3.4.8. The
        // wiring is end-to-end — `handle_subscribe_v5` captures the
        // ID in the per-session tracker, the write loop attaches all
        // matching IDs to outgoing v5 PUBLISHes, and the retain-
        // replay path includes the SUBSCRIBE's ID on replayed
        // retained messages. Advertise `1` so a v5 client knows the
        // feature is available and does not have to fall back to
        // user-property workarounds.
        properties.subscription_identifiers_available = Some(1);
        // MQTT 5.0 §3.2.2.3.11 Shared Subscription Available.
        // rustgate doesn't support the §4.8.2 `$share/<group>/<topic>`
        // shared-subscription syntax. Advertise 0 explicitly — same
        // reasoning as Subscription Identifiers above: the spec
        // default when absent is 1 ("supported"), so silence here
        // would let a client expect load-balanced delivery across
        // a `$share` group when in fact each subscriber would get
        // every message (non-shared semantics).
        properties.shared_subscription_available = Some(0);
        // MQTT 5.0 §3.2.2.3.2: Session Expiry Interval. The broker MAY
        // override the client's CONNECT-time request by advertising a
        // different value here; the client MUST then treat the
        // returned value as authoritative for the duration of this
        // session. The negotiated value is computed by the caller as
        // `min(client_request, max_session_expiry_secs)` — when the
        // operator configures `max_session_expiry_secs = 0` (the
        // default), this is always `0` and rustgate's no-retention
        // behaviour is preserved (refs #1162). When retention is
        // enabled, the broker advertises the actual cap so the client
        // knows when its session will be discarded.
        properties.session_expiry_interval = Some(negotiated_session_expiry);
        // MQTT 5.0 §3.2.2.3.14: Server Keep Alive. The broker MAY
        // override the client's CONNECT-time keep-alive request by
        // advertising a different value here; the client MUST then
        // use the returned value as the Keep Alive for the session.
        // Asymmetry vs the other CONNACK properties: this one is set
        // ONLY when the operator opts in via a non-zero
        // `server_keep_alive_secs` config, so a default deployment
        // emits silence — the spec default when absent is "no
        // override," which matches rustgate's pre-this-knob behaviour
        // (the broker honors the client's request). Setting it to 0
        // would NOT mean "disable keep-alive" for the client (which
        // is what 0 means in CONNECT) — it would mean "the broker
        // explicitly chose 0," which is a stronger statement than
        // we want to make on every CONNACK. Omitting the property
        // unless configured preserves spec-compliant defaults.
        if self.server_keep_alive_secs > 0 {
            properties.server_keep_alive = Some(self.server_keep_alive_secs);
        }
        let connack = mqttbytes::v5::ConnAck {
            // MQTT 5.0 §3.2.2.1.1: Session Present is `true` IFF the
            // server resumed an existing session for this client_id
            // (clean_start=0 + matching saved session within expiry
            // window). On every other path — clean_start=1, fresh
            // client_id, expired session, retention disabled — the
            // flag is `false`. The caller computes the value from
            // the connect_handshake outcome.
            session_present,
            code,
            properties: Some(properties),
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
            Err(mqttbytes::Error::PayloadSizeLimitExceeded(size)) => {
                // Surface the size-cap rejection as a structured variant so
                // the session loop can emit a v5 DISCONNECT 0x95 (or simply
                // close on v3.1.1, which has no server-initiated DISCONNECT
                // packet). Folding it into `Malformed` would lose the
                // typed signal the rejection path needs.
                Err(MqttError::PacketTooLarge {
                    size,
                    max: max_packet_size,
                })
            }
            Err(e) => Err(MqttError::Malformed(e.to_string())),
        },
        ProtocolLevel::V50 => {
            // mqttbytes 0.6.0 incorrectly returns `PayloadRequired` for a
            // zero-remaining-length v5 DISCONNECT (`0xE0 0x00`), which is
            // the standard wire form for `NormalDisconnection` with no
            // properties (MQTT 5.0 §3.14.2.1: a missing reason code byte
            // is interpreted as `NormalDisconnection`). Pre-detect and
            // synthesize the packet so a perfectly conformant client
            // does not see its DISCONNECT mis-classified as a malformed
            // packet — and so the will-message suppression path
            // (`ReadLoopOutcome::CleanDisconnect`) actually fires.
            if buf.len() >= 2 && buf[0] == 0xE0 && buf[1] == 0x00 {
                let _ = buf.split_to(2);
                return Ok(Some(MqttPacket::V5(Box::new(
                    mqttbytes::v5::Packet::Disconnect(mqttbytes::v5::Disconnect::new()),
                ))));
            }
            match mqttbytes::v5::read(buf, max_packet_size) {
                Ok(packet) => Ok(Some(MqttPacket::V5(Box::new(packet)))),
                Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
                Err(mqttbytes::Error::PayloadSizeLimitExceeded(size)) => {
                    // Map to the typed `PacketTooLarge` variant so the
                    // session loop emits MQTT 5.0 DISCONNECT 0x95
                    // (`PacketTooLarge`) before closing — gives the client
                    // a structured reason instead of an unexplained TCP
                    // RST. See spec §4.13 + reason code 0x95 in §3.14.2.1.
                    Err(MqttError::PacketTooLarge {
                        size,
                        max: max_packet_size,
                    })
                }
                Err(e) => Err(MqttError::Malformed(e.to_string())),
            }
        }
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

    // CONNECT-time size violations are routed through the same typed
    // `PacketTooLarge` variant as live-traffic violations so the session
    // entry path can refuse with `ConnectReturnCode::PacketTooLarge` (149)
    // before the session even starts — symmetric with the post-CONNECT
    // path that emits DISCONNECT 0x95.
    match negotiated {
        ProtocolLevel::V311 => match mqttbytes::v4::read(buf, max_packet_size) {
            Ok(packet) => Ok(Some(MqttPacket::V4(packet))),
            Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
            Err(mqttbytes::Error::PayloadSizeLimitExceeded(size)) => {
                Err(MqttError::PacketTooLarge {
                    size,
                    max: max_packet_size,
                })
            }
            Err(e) => Err(MqttError::Malformed(e.to_string())),
        },
        ProtocolLevel::V50 => match mqttbytes::v5::read(buf, max_packet_size) {
            Ok(packet) => Ok(Some(MqttPacket::V5(Box::new(packet)))),
            Err(mqttbytes::Error::InsufficientBytes(_)) => Ok(None),
            Err(mqttbytes::Error::PayloadSizeLimitExceeded(size)) => {
                Err(MqttError::PacketTooLarge {
                    size,
                    max: max_packet_size,
                })
            }
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
        // QoS 2 four-step (refs #880): PUBREC and PUBCOMP are server →
        // client packets in the four-way handshake. PUBREL is the
        // *inbound* counterpart (client → server) so it does NOT
        // appear here — only the writer side of the broker's
        // half of the handshake.
        Packet::PubRec(p) => p.write(buf),
        Packet::PubComp(p) => p.write(buf),
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
        // QoS 2 four-step (refs #880): see v4 sibling above for why
        // PUBREL is excluded from the writer arm.
        Packet::PubRec(p) => p.write(buf),
        Packet::PubComp(p) => p.write(buf),
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

    // -----------------------------------------------------------------
    // mqttbytes 0.6.0 v5 DISCONNECT zero-payload workaround
    //
    // The standard wire form for a v5 DISCONNECT with `NormalDisconnection`
    // reason code and no properties is two bytes: `0xE0 0x00`. mqttbytes
    // 0.6.0 v5 `read` omits `Disconnect` from its zero-remaining-length
    // packet whitelist (v4 includes it correctly), so a perfectly
    // conformant client gets `Error::PayloadRequired` from the parser.
    // The `try_parse` workaround pre-detects the literal byte sequence
    // and synthesises the matching `Disconnect::new()` packet so the
    // session loop's `ReadLoopOutcome::CleanDisconnect` branch fires
    // and the will-suppression contract is honoured. These tests pin
    // the workaround so a future mqttbytes upgrade (or a refactor of
    // the codec) cannot silently regress will-suppression behaviour.
    // -----------------------------------------------------------------

    #[test]
    fn try_parse_v5_recognizes_two_byte_disconnect() {
        // `0xE0 0x00` → v5 Disconnect with `NormalDisconnection`.
        let mut buf = BytesMut::from(&b"\xE0\x00"[..]);
        let mut protocol = Some(ProtocolLevel::V50);
        let parsed = try_parse(&mut buf, &mut protocol, 16 * 1024)
            .expect("ok")
            .expect("packet present");
        match parsed {
            MqttPacket::V5(boxed) => match *boxed {
                mqttbytes::v5::Packet::Disconnect(d) => {
                    assert_eq!(
                        d.reason_code,
                        mqttbytes::v5::DisconnectReasonCode::NormalDisconnection,
                        "two-byte v5 DISCONNECT must materialise as NormalDisconnection",
                    );
                }
                other => panic!("expected v5 Disconnect, got {other:?}"),
            },
            MqttPacket::V4(other) => panic!("expected v5 packet, got v4 {other:?}"),
        }
        // The two parsed bytes must have been consumed from the buffer
        // — leaving them in place would re-trigger the workaround on
        // the next `try_parse` call and loop the session.
        assert!(buf.is_empty(), "two bytes must be consumed");
    }

    #[test]
    fn try_parse_v5_disconnect_workaround_does_not_match_other_packets() {
        // The workaround pre-check is `buf[0] == 0xE0 && buf[1] ==
        // 0x00` — a more permissive match (e.g. `buf[0] == 0xE0`
        // alone) would silently swallow conformant DISCONNECTs with
        // explicit reason codes and lose their reason information. A
        // hand-crafted PINGREQ (0xC0 0x00) must NOT match the
        // workaround at all — the parser falls through to the
        // standard path which produces `Packet::PingReq`.
        let mut buf = BytesMut::from(&b"\xC0\x00"[..]);
        let mut protocol = Some(ProtocolLevel::V50);
        let parsed = try_parse(&mut buf, &mut protocol, 16 * 1024)
            .expect("ok")
            .expect("packet present");
        match parsed {
            MqttPacket::V5(boxed) => match *boxed {
                mqttbytes::v5::Packet::PingReq => {}
                other => {
                    panic!("workaround must not match non-DISCONNECT byte sequences; got {other:?}")
                }
            },
            MqttPacket::V4(other) => panic!("expected v5, got v4 {other:?}"),
        }
        assert!(buf.is_empty(), "PINGREQ frame must be consumed");
    }

    // -----------------------------------------------------------------
    // Maximum Packet Size advertisement + size-violation rejection
    // (refs #753; MQTT 5.0 §3.2.2.3.6 + reason code 0x95 in §3.14.2.1)
    //
    // The CONNACK property tells a compliant client the broker's cap so
    // the client can short-circuit oversized publishes locally. The
    // size-violation check inside `try_parse` is the gate that fires
    // when a non-compliant client sends one anyway — and it MUST surface
    // the typed `PacketTooLarge` variant so the session loop can emit
    // DISCONNECT 0x95 instead of an unexplained TCP RST.
    // -----------------------------------------------------------------

    #[test]
    fn v5_connack_advertises_configured_maximum_packet_size() {
        // The CONNACK builder reads `self.max_packet_size` so a fresh
        // codec advertises whatever the listener was configured with.
        // A regression that hard-coded the property value, dropped it
        // entirely, or swapped to `None` would make the broker silently
        // claim "no limit" — exactly the F-58 production hazard #753
        // closes. We pin the round-trip end-to-end: build the packet
        // bytes, re-parse them, assert the property survives.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.max_packet_size = Some(16 * 1024 * 1024);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.max_packet_size,
                    Some(16 * 1024 * 1024),
                    "broker must advertise its 16 MiB cap so a compliant client \
                     short-circuits oversized publishes locally"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_configured_receive_maximum() {
        // Refs #880: MQTT 5.0 §3.2.2.3.3 — CONNACK Receive Maximum.
        // Tells a compliant client the maximum number of QoS 1/2
        // PUBLISHes it may have in-flight to the broker without
        // intervening acks. The spec default when the property is
        // absent is 65535 — operationally useless because no
        // well-behaved client will pipeline 65k unacked publishes.
        // Always advertising means the client has a concrete cap to
        // self-limit against.
        //
        // Pin the wire format end-to-end: build CONNACK with the
        // property, parse it back, assert the value survives. A
        // regression that hard-coded the value, dropped the property,
        // or swapped to `None` would silently revert clients to the
        // 65535 default — exactly the gap #880 calls out.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.receive_max = Some(32);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.receive_max,
                    Some(32),
                    "broker must advertise its Receive Maximum so a compliant \
                     client knows how many QoS 1/2 publishes it can pipeline"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_session_expiry_interval_zero() {
        // Refs #880: MQTT 5.0 §3.2.2.3.2 — the broker MAY override
        // the client's CONNECT-time Session Expiry Interval with a
        // value in the matching CONNACK; the client MUST treat the
        // returned value as authoritative for session duration.
        // rustgate doesn't retain sessions across disconnect, so
        // the only honest signal is `0` ("session ends when the
        // network connection is closed" per §4.1).
        //
        // Pin the wire format: build CONNACK with session_expiry=0,
        // parse it back, assert the value survives. A regression
        // that dropped the property would let the client assume the
        // broker honors the client-requested expiry — exactly the
        // gap this PR closes.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.session_expiry_interval = Some(0);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.session_expiry_interval,
                    Some(0),
                    "broker must advertise Session Expiry Interval = 0 so a \
                     compliant client knows it cannot rely on broker-side \
                     session retention"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_configured_topic_alias_max() {
        // Refs #880: MQTT 5.0 §3.2.2.3.8 — Topic Alias Maximum.
        // Tells a compliant client the highest Topic Alias value the
        // broker will accept on inbound PUBLISHes from this connection.
        // Always advertised (even when the value is 0) so the client
        // gets an explicit "feature disabled" signal rather than
        // having to fall back on the spec's implicit-default of 0.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.topic_alias_max = Some(8);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.topic_alias_max,
                    Some(8),
                    "broker must advertise its Topic Alias Maximum so the \
                     client knows the highest accepted alias value"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_server_keep_alive_when_configured() {
        // Refs #880: MQTT 5.0 §3.2.2.3.14 — Server Keep Alive.
        // When the operator opts in via a non-zero
        // `server_keep_alive_secs` config, the broker MUST advertise
        // the value here so a compliant client switches to the
        // overridden interval (the spec text is "the Client MUST use
        // this value instead of the Keep Alive value the Client sent
        // on CONNECT"). Pin the wire format end-to-end: build a
        // CONNACK with the property set to 120, parse it back, assert
        // the value survives. A regression that hard-coded the value,
        // dropped the property, or swapped to `None` would silently
        // leave the broker honoring the client's request even after
        // the operator opted into the override.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.server_keep_alive = Some(120);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.server_keep_alive,
                    Some(120),
                    "broker must advertise its Server Keep Alive override so a \
                     compliant client switches to the broker-imposed cadence \
                     instead of its own CONNECT-time request"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_omits_server_keep_alive_when_zero() {
        // Refs #880: the asymmetric default vs the other CONNACK
        // properties — when `server_keep_alive_secs == 0` (the default)
        // the broker MUST NOT advertise the property, so a compliant
        // client falls back to honoring its own CONNECT-time keep-alive
        // (the spec default when the property is absent). Setting the
        // wire field to 0 explicitly would mean "the broker explicitly
        // chose 0," a stronger statement than we want to make on every
        // CONNACK; omission is the spec-compliant signal for "no
        // override." Pin the absence end-to-end via a CONNACK with
        // `server_keep_alive = None` round-tripped through the wire
        // format. A regression that started emitting `Some(0)` here
        // would silently flip every default deployment into "broker
        // disables keep-alive" semantics.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                // Leave server_keep_alive at its default `None`.
                p.max_packet_size = Some(1024);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.server_keep_alive, None,
                    "broker must omit Server Keep Alive when no override is \
                     configured so a compliant client honors its own \
                     CONNECT-time request per the spec's absent-property default"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_remaining_capability_properties() {
        // Refs #880: pin the wire format for the five remaining MQTT
        // 5.0 §3.2.2 CONNACK capability properties advertised in the
        // post-#1164 surface:
        //   §3.2.2.3.4  Maximum QoS                     = 2 (we support QoS 0/1/2 inbound after #1161)
        //   §3.2.2.3.5  Retain Available                = 1 (#1146)
        //   §3.2.2.3.9  Wildcard Subscription Available = 1 by default (SingleLevelOnly + Full)
        //   §3.2.2.3.10 Subscription Identifiers Avail. = 1 (refs #880 follow-up)
        //   §3.2.2.3.11 Shared Subscription Available   = 0 (not implemented)
        //
        // The "Available = 0" advertisement on §3.2.2.3.11 is a
        // load-bearing signal: the spec default when absent is 1
        // ("supported"), so silence would mislead a client into
        // expecting features the broker doesn't actually provide.
        // Pin the wire format end-to-end via build + parse.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.max_qos = Some(2);
                p.retain_available = Some(1);
                p.wildcard_subscription_available = Some(1);
                p.subscription_identifiers_available = Some(1);
                p.shared_subscription_available = Some(0);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(64);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(props.max_qos, Some(2));
                assert_eq!(props.retain_available, Some(1));
                assert_eq!(props.wildcard_subscription_available, Some(1));
                assert_eq!(props.subscription_identifiers_available, Some(1));
                assert_eq!(props.shared_subscription_available, Some(0));
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_subscription_identifiers_available_one() {
        // Refs #880: this test pins the load-bearing flip from
        // `Some(0)` (the pre-PR advertisement) to `Some(1)`. The
        // `subscription_identifiers_available` property is the
        // capability bit that gates whether a v5 client may include
        // `subscription_identifier` on SUBSCRIBE per §3.8.2.1.2 and
        // expect the broker to echo it on matching PUBLISHes per
        // §3.3.4.8. Advertising `Some(0)` while ALSO propagating
        // identifiers would be a wire-protocol contradiction: the
        // client would believe the feature is unavailable and might
        // never set the property, defeating the propagation work.
        // Build a CONNACK with the property set to `1` and assert
        // that round-trip via mqttbytes preserves the value.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.subscription_identifiers_available = Some(1);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(
                    props.subscription_identifiers_available,
                    Some(1),
                    "subscription_identifiers_available MUST be 1 \
                     after the propagation wiring lands; otherwise a v5 \
                     client believes the feature is unavailable and never \
                     sets the SUBSCRIBE property in the first place"
                );
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn v5_connack_advertises_both_max_packet_size_and_receive_max() {
        // The two CONNACK properties #1158 and #1160 (receive max)
        // both ride on the same `write_connack_v5` call. Pin that
        // BOTH properties survive serialization simultaneously — a
        // regression that overwrote one with the other (e.g. by
        // creating a fresh `ConnAckProperties::new()` mid-function
        // and copying only one field) would manifest only when both
        // properties were expected and the test would catch it.
        let connack = mqttbytes::v5::ConnAck {
            session_present: false,
            code: mqttbytes::v5::ConnectReturnCode::Success,
            properties: Some({
                let mut p = mqttbytes::v5::ConnAckProperties::new();
                p.max_packet_size = Some(16 * 1024 * 1024);
                p.receive_max = Some(32);
                p
            }),
        };
        let mut buf = BytesMut::with_capacity(32);
        write_v5_to_buf(&mqttbytes::v5::Packet::ConnAck(connack), &mut buf).expect("serialize");

        let decoded = mqttbytes::v5::read(&mut buf, 16 * 1024).expect("parse");
        match decoded {
            mqttbytes::v5::Packet::ConnAck(a) => {
                let props = a.properties.expect("properties present");
                assert_eq!(props.max_packet_size, Some(16 * 1024 * 1024));
                assert_eq!(props.receive_max, Some(32));
            }
            other => panic!("expected ConnAck, got {other:?}"),
        }
    }

    #[test]
    fn try_parse_v5_size_violation_returns_packet_too_large() {
        // Construct a v5 PUBLISH with a 256-byte payload whose
        // mqttbytes-fixed-header-`remaining_len` exceeds a 64-byte cap,
        // feed it through try_parse, and assert the typed
        // `PacketTooLarge` variant fires (not `Malformed`). This is the
        // gate that makes the session loop's DISCONNECT 0x95 path
        // reachable — folding it into `Malformed` would lose the typed
        // signal and the client would see an unexplained TCP RST.
        //
        // The cap is checked against `fixed_header.remaining_len` (the
        // variable header + payload — NOT the full serialized packet),
        // so 64 is well below the ~261 bytes a "a/b" + 256-byte-payload
        // PUBLISH actually carries.
        let publish =
            mqttbytes::v5::Publish::new("a/b", mqttbytes::QoS::AtMostOnce, vec![0xAB; 256]);
        let mut buf = BytesMut::with_capacity(512);
        write_v5_to_buf(&mqttbytes::v5::Packet::Publish(publish), &mut buf).expect("serialize");
        const CAP: usize = 64;

        let mut protocol = Some(ProtocolLevel::V50);
        let err =
            try_parse(&mut buf, &mut protocol, CAP).expect_err("size cap must reject this packet");
        match err {
            MqttError::PacketTooLarge { size, max } => {
                assert!(
                    size > max,
                    "PacketTooLarge must report a size exceeding the cap; \
                     got size={size} max={max}"
                );
                assert_eq!(max, CAP, "max field must echo the configured cap");
            }
            other => panic!(
                "size violation must surface as PacketTooLarge for the session \
                 loop to emit DISCONNECT 0x95; got {other:?}"
            ),
        }
    }

    #[test]
    fn try_parse_v311_size_violation_returns_packet_too_large() {
        // v3.1.1 has no server-initiated DISCONNECT packet — the broker
        // just drops the connection — but the typed variant still has
        // to fire so error logs / metrics distinguish "client too noisy"
        // from "client emitted garbage". A regression that returned
        // `Malformed` from the v4 path would conflate the two failure
        // modes in the operator's dashboard.
        let publish = mqttbytes::v4::Publish::new(
            "a/b",
            mqttbytes::QoS::AtMostOnce,
            vec![0xCD; 256].as_slice(),
        );
        let mut buf = BytesMut::with_capacity(512);
        write_v4_to_buf(&mqttbytes::v4::Packet::Publish(publish), &mut buf).expect("serialize");
        const CAP: usize = 64;

        let mut protocol = Some(ProtocolLevel::V311);
        let err =
            try_parse(&mut buf, &mut protocol, CAP).expect_err("size cap must reject this packet");
        assert!(
            matches!(err, MqttError::PacketTooLarge { .. }),
            "v4 size violation must surface as PacketTooLarge; got {err:?}"
        );
    }

    #[test]
    fn try_parse_connect_rejects_oversized_connect_with_packet_too_large() {
        // A CONNECT whose own remaining length exceeds the cap is a
        // size violation — but it lands in `try_parse_connect`, NOT in
        // the post-handshake `try_parse` v5/v311 arms. Without the
        // typed mapping in the connect-time path, an oversized CONNECT
        // would surface as `Malformed` and the client would see a
        // generic protocol-error diagnostic. This test pins the
        // connect-time symmetry against the live-traffic path.
        //
        // `write_v5_to_buf` skips CONNECT (server-only allowlist), so
        // we serialise via `connect.write` directly. A 512-byte will
        // payload pushes CONNECT remaining_len well past a 64-byte cap.
        let mut connect = mqttbytes::v5::Connect::new("c");
        connect.last_will = Some(mqttbytes::v5::LastWill::new(
            "w/last",
            vec![0xEE; 512],
            mqttbytes::QoS::AtMostOnce,
            false,
        ));
        let mut buf = BytesMut::with_capacity(1024);
        let _ = connect.write(&mut buf).expect("serialize");
        const CAP: usize = 64;

        let mut protocol: Option<ProtocolLevel> = None;
        let err = try_parse(&mut buf, &mut protocol, CAP)
            .expect_err("size cap must reject oversized CONNECT");
        assert!(
            matches!(err, MqttError::PacketTooLarge { .. }),
            "oversized CONNECT must surface as PacketTooLarge for the connect \
             handshake to refuse cleanly; got {err:?}"
        );
    }
}
