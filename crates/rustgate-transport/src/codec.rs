// Copyright © 2026 Roberto Chiofalo.

//! Message framing codecs.

use std::io;

use rustgate_core::constants::MAX_FRAME_SIZE;
use rustgate_core::protocol::{FramingStrategy, HeaderSize};
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum XML nesting depth before rejecting the stream.
/// Prevents resource exhaustion from pathological nesting (e.g., `<a><a><a>...`).
/// CoT events are typically 3-4 levels deep; 256 is generous.
const MAX_XML_DEPTH: usize = 256;

#[derive(Debug)]
pub enum FramedCodec {
    LengthPrefixed(LengthPrefixedCodec),
    XmlStream(XmlStreamCodec),
    LineDelimited(LineDelimitedCodec),
    /// Protobuf varint length-delimited framing (no magic prefix) — used by
    /// SAPIENT and other plain length-delimited protobuf streams. Selected
    /// directly by the tactical stream-ingress listener rather than via
    /// [`FramingStrategy`] auto-detection (a bare varint has no signature to
    /// detect), so it has no `try_from_strategy` arm.
    VarintDelimited(VarintDelimitedCodec),
    /// Length-inside-a-fixed-header framing (Link 16 JREAP-C). Also
    /// listener-selected, so no `try_from_strategy` arm.
    HeaderLength(HeaderLengthCodec),
    #[cfg(feature = "proto")]
    TakProtobuf(rustgate_proto::TakFrameCodec),
    #[cfg(feature = "mavlink")]
    Mavlink(rustgate_mavlink::MavlinkFrameCodec),
}

/// Reasons [`FramedCodec::try_from_strategy`] can fail.
///
/// The only failure mode today is a request for a strategy whose crate
/// feature is not enabled in the current build. Startup validation in
/// `rustgate-server` is expected to reject those configurations early,
/// so in practice the error path is hit only if a SIGHUP-reloaded
/// config or a logic bug lets an unsupported strategy reach the
/// session pipeline. Returning an error instead of panicking keeps the
/// process alive and lets the caller respond with a structured close
/// — important under `panic = "abort"` release profiles where a
/// panic would take down every in-flight connection.
#[derive(Debug, thiserror::Error)]
pub enum FramedCodecError {
    /// The requested framing strategy is not available in this build
    /// because its cargo feature is disabled. The field is the feature
    /// name, e.g. `"proto"` or `"mavlink"`.
    #[error(
        "framing strategy not available in this build: missing cargo feature `{feature}`; \
         rebuild with `--features {feature}` or reconfigure the listener"
    )]
    FeatureNotEnabled {
        /// The cargo feature name the strategy requires.
        feature: &'static str,
    },
}

impl From<FramedCodecError> for io::Error {
    fn from(err: FramedCodecError) -> Self {
        // `InvalidInput` is the correct kind for "configuration requests
        // something we do not support" — the data on the wire is fine,
        // the caller handed us an unsupported selector.
        io::Error::new(io::ErrorKind::InvalidInput, err.to_string())
    }
}

impl FramedCodec {
    /// Construct a codec for the given framing strategy, returning
    /// `Err(FramedCodecError::FeatureNotEnabled { .. })` if the
    /// strategy requires a crate feature that was not built in.
    ///
    /// This replaces the pre-#750 infallible `from_strategy` that
    /// used `unreachable!()` on the disabled-feature branch — which,
    /// with the workspace-wide `panic = "abort"` release profile,
    /// would have aborted the process if a mis-routed SIGHUP reload
    /// ever pointed a listener at a disabled codec.
    pub fn try_from_strategy(strategy: &FramingStrategy) -> Result<Self, FramedCodecError> {
        Ok(match strategy {
            FramingStrategy::LengthPrefixed { header_size } => {
                Self::LengthPrefixed(LengthPrefixedCodec::new(*header_size))
            }
            FramingStrategy::XmlStream => Self::XmlStream(XmlStreamCodec::new()),
            FramingStrategy::LineDelimited => Self::LineDelimited(LineDelimitedCodec::new()),
            #[cfg(feature = "proto")]
            FramingStrategy::TakProtobuf => Self::TakProtobuf(rustgate_proto::TakFrameCodec::new()),
            #[cfg(not(feature = "proto"))]
            FramingStrategy::TakProtobuf => {
                return Err(FramedCodecError::FeatureNotEnabled { feature: "proto" });
            }
            #[cfg(feature = "mavlink")]
            FramingStrategy::Mavlink => Self::Mavlink(rustgate_mavlink::MavlinkFrameCodec::new()),
            #[cfg(not(feature = "mavlink"))]
            FramingStrategy::Mavlink => {
                return Err(FramedCodecError::FeatureNotEnabled { feature: "mavlink" });
            }
        })
    }
}

impl Decoder for FramedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            Self::LengthPrefixed(c) => c.decode(src),
            Self::XmlStream(c) => c.decode(src),
            Self::LineDelimited(c) => c.decode(src),
            Self::VarintDelimited(c) => c.decode(src),
            Self::HeaderLength(c) => c.decode(src),
            #[cfg(feature = "proto")]
            Self::TakProtobuf(c) => c.decode(src),
            #[cfg(feature = "mavlink")]
            Self::Mavlink(c) => c.decode(src),
        }
    }
}

impl Encoder<BytesMut> for FramedCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Self::LengthPrefixed(c) => c.encode(item, dst),
            Self::XmlStream(c) => c.encode(item, dst),
            Self::LineDelimited(c) => c.encode(item, dst),
            Self::VarintDelimited(c) => c.encode(item, dst),
            Self::HeaderLength(c) => c.encode(item, dst),
            #[cfg(feature = "proto")]
            Self::TakProtobuf(c) => c.encode(item, dst),
            #[cfg(feature = "mavlink")]
            Self::Mavlink(c) => c.encode(item, dst),
        }
    }
}

#[derive(Debug)]
pub struct LengthPrefixedCodec {
    header_size: HeaderSize,
    pending_len: Option<usize>,
    /// Configurable maximum frame size. Defaults to `MAX_FRAME_SIZE` if not set.
    max_frame_size: usize,
}

#[derive(Debug, Default)]
pub struct XmlStreamCodec {
    depth: usize,
}

impl LengthPrefixedCodec {
    pub fn new(header_size: HeaderSize) -> Self {
        Self {
            header_size,
            pending_len: None,
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Create a codec with a custom maximum frame size.
    ///
    /// Use this to enforce a tighter limit than the global `MAX_FRAME_SIZE`
    /// constant, for example to match a configuration-level `max_message_size`.
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    fn header_bytes(&self) -> usize {
        self.header_size.byte_count()
    }

    fn read_length(&self, src: &[u8]) -> usize {
        match self.header_size {
            HeaderSize::One => src[0] as usize,
            HeaderSize::Two => u16::from_be_bytes([src[0], src[1]]) as usize,
            HeaderSize::Four => u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize,
        }
    }

    fn write_length(&self, len: usize, dst: &mut BytesMut) {
        match self.header_size {
            HeaderSize::One => dst.put_u8(len as u8),
            HeaderSize::Two => dst.put_u16(len as u16),
            HeaderSize::Four => dst.put_u32(len as u32),
        }
    }

    fn max_payload_size(&self) -> usize {
        let header_max = match self.header_size {
            HeaderSize::One => u8::MAX as usize,
            HeaderSize::Two => u16::MAX as usize,
            HeaderSize::Four => u32::MAX as usize,
        };
        header_max.min(self.max_frame_size)
    }
}

impl Decoder for LengthPrefixedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let payload_len = match self.pending_len {
            Some(len) => len,
            None => {
                if src.len() < self.header_bytes() {
                    return Ok(None);
                }
                let len = self.read_length(&src[..self.header_bytes()]);
                if len > self.max_frame_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "frame too large: {} bytes exceeds limit of {}",
                            len, self.max_frame_size
                        ),
                    ));
                }
                src.advance(self.header_bytes());
                self.pending_len = Some(len);
                len
            }
        };

        if src.len() < payload_len {
            src.reserve(payload_len - src.len());
            return Ok(None);
        }

        self.pending_len = None;
        Ok(Some(src.split_to(payload_len)))
    }
}

impl Encoder<BytesMut> for LengthPrefixedCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let max_len = self.max_payload_size();
        if item.len() > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {} > {}", item.len(), max_len),
            ));
        }
        dst.reserve(self.header_bytes() + item.len());
        self.write_length(item.len(), dst);
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Protobuf varint length-delimited framing: a base-128 LEB-encoded payload
/// length, then exactly that many payload bytes. No magic prefix — used by
/// SAPIENT (BSI Flex 335) and other plain length-delimited protobuf streams.
///
/// # Security
///
/// The decoded length is bounded **before** any buffer reservation: a
/// length-prefix above `max_frame_size` is rejected with `InvalidData`
/// rather than allocated, and a varint that does not terminate within 10
/// bytes (the maximum for a 64-bit value) is rejected — so a hostile peer
/// cannot drive an unbounded allocation or an unbounded prefix scan.
#[derive(Debug)]
pub struct VarintDelimitedCodec {
    max_frame_size: usize,
}

impl Default for VarintDelimitedCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl VarintDelimitedCodec {
    /// Maximum number of bytes a base-128 varint may occupy for a 64-bit
    /// length. A prefix longer than this is malformed (or hostile padding).
    const MAX_VARINT_BYTES: usize = 10;

    /// Codec with the global [`MAX_FRAME_SIZE`] cap.
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Codec with a tighter per-frame cap than [`MAX_FRAME_SIZE`].
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size.min(MAX_FRAME_SIZE);
        self
    }
}

impl Decoder for VarintDelimitedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Parse the LEB128 length prefix at the front WITHOUT consuming it,
        // so a partially-arrived frame leaves the buffer intact for the
        // next read. Re-parsing the (≤10-byte) prefix per call is cheap.
        let mut payload_len: u64 = 0;
        let mut shift: u32 = 0;
        let mut header = 0usize;
        loop {
            if header >= src.len() {
                // Varint not fully arrived yet — wait for more bytes.
                return Ok(None);
            }
            if header >= Self::MAX_VARINT_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "varint length prefix exceeds 10 bytes (malformed)",
                ));
            }
            let byte = src[header];
            header += 1;
            payload_len |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        let payload_len = usize::try_from(payload_len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "frame length overflows usize")
        })?;
        // Bound BEFORE reserving — no allocation driven by an attacker length.
        if payload_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame too large: {} bytes exceeds limit of {}",
                    payload_len, self.max_frame_size
                ),
            ));
        }

        let total = header + payload_len;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        // Drop the length prefix, then split off exactly one payload frame.
        src.advance(header);
        Ok(Some(src.split_to(payload_len)))
    }
}

impl Encoder<BytesMut> for VarintDelimitedCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {} > {}", item.len(), self.max_frame_size),
            ));
        }
        let mut len = item.len() as u64;
        loop {
            let mut byte = (len & 0x7F) as u8;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            dst.put_u8(byte);
            if len == 0 {
                break;
            }
        }
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Framing where the payload length lives **inside** a fixed-size header at
/// a fixed offset, and the delimited frame **includes** that header (the
/// length field counts only the bytes *after* the header).
///
/// This is the Link 16 JREAP-C shape: a 16-byte header whose `body_length`
/// `u32` sits at offset 12, with the body following. Unlike
/// [`LengthPrefixedCodec`] (where the length is a leading prefix that is
/// stripped), this yields `header + body` as one frame so the protocol codec
/// can parse its own header.
///
/// # Security
///
/// The body length is bounded by `max_frame_size` **before** any buffer
/// reservation — a hostile `body_length` cannot drive an unbounded
/// allocation.
///
/// Decode-only: [`Encoder`] returns an error, because the header is
/// protocol-owned (this codec does not know how to synthesize it).
#[derive(Debug)]
pub struct HeaderLengthCodec {
    header_len: usize,
    length_offset: usize,
    length_size: HeaderSize,
    max_frame_size: usize,
}

impl HeaderLengthCodec {
    /// `header_len` = total header bytes; `length_offset` = byte offset of
    /// the big-endian length field within the header; `length_size` = its
    /// width. The length value counts bytes following the header.
    pub fn new(header_len: usize, length_offset: usize, length_size: HeaderSize) -> Self {
        Self {
            header_len,
            length_offset,
            length_size,
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Tighten the per-frame body cap below [`MAX_FRAME_SIZE`].
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size.min(MAX_FRAME_SIZE);
        self
    }

    fn read_body_length(&self, header: &[u8]) -> usize {
        let o = self.length_offset;
        match self.length_size {
            HeaderSize::One => header[o] as usize,
            HeaderSize::Two => u16::from_be_bytes([header[o], header[o + 1]]) as usize,
            HeaderSize::Four => {
                u32::from_be_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]])
                    as usize
            }
        }
    }
}

impl Decoder for HeaderLengthCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need the whole header before the embedded length field is readable.
        if src.len() < self.header_len {
            return Ok(None);
        }
        // SEC-8: the length field must lie fully within the header, or
        // `read_body_length` indexes past `header_len` and panics. `new` is
        // intentionally infallible (it is built inside a non-fallible
        // ingress closure), so a misconfigured offset/size is caught here
        // and reported as `InvalidData` rather than aborting the task.
        let length_width = match self.length_size {
            HeaderSize::One => 1usize,
            HeaderSize::Two => 2,
            HeaderSize::Four => 4,
        };
        // `overflowing_add` (not `saturating_add`) so a pathological
        // `length_offset` near `usize::MAX` is treated as out-of-bounds
        // rather than silently saturating to a value that could equal
        // `header_len`.
        let (length_field_end, offset_overflowed) =
            self.length_offset.overflowing_add(length_width);
        if offset_overflowed || length_field_end > self.header_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "length field at offset {} (+{length_width} bytes) does not fit in {}-byte header",
                    self.length_offset, self.header_len
                ),
            ));
        }
        let body_len = self.read_body_length(&src[..self.header_len]);
        // Bound BEFORE reserving — no attacker-driven allocation.
        if body_len > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame body too large: {} bytes exceeds limit of {}",
                    body_len, self.max_frame_size
                ),
            ));
        }
        let total = self.header_len + body_len;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }
        // Yield the full frame (header + body).
        Ok(Some(src.split_to(total)))
    }
}

impl Encoder<BytesMut> for HeaderLengthCodec {
    type Error = io::Error;

    fn encode(&mut self, _item: BytesMut, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HeaderLengthCodec is decode-only: the header is protocol-owned",
        ))
    }
}

impl XmlStreamCodec {
    pub fn new() -> Self {
        Self::default()
    }

    fn find_element_end(&mut self, src: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < src.len() {
            if src[i] != b'<' {
                i += 1;
                continue;
            }

            if i + 1 >= src.len() {
                return None;
            }

            match src[i + 1] {
                b'/' => {
                    let close = self.find_tag_end(src, i)?;
                    if self.depth == 0 {
                        return None;
                    }
                    self.depth -= 1;
                    if self.depth == 0 {
                        return Some(close + 1);
                    }
                    i = close + 1;
                }
                b'?' => {
                    let close = self.find_pi_end(src, i)?;
                    i = close;
                }
                b'!' => {
                    let close = self.find_markup_end(src, i)?;
                    i = close;
                }
                _ => {
                    let close = self.find_tag_end(src, i)?;
                    let is_self_closing = close > 0 && src[close - 1] == b'/';
                    if is_self_closing {
                        if self.depth == 0 {
                            return Some(close + 1);
                        }
                    } else {
                        self.depth += 1;
                    }
                    i = close + 1;
                }
            }
        }
        None
    }

    fn find_tag_end(&self, src: &[u8], start: usize) -> Option<usize> {
        let mut i = start;
        while i < src.len() {
            match src[i] {
                b'"' => i = self.skip_quoted(src, i, b'"')?,
                b'\'' => i = self.skip_quoted(src, i, b'\'')?,
                b'>' => return Some(i),
                _ => i += 1,
            }
        }
        None
    }

    fn find_pi_end(&self, src: &[u8], start: usize) -> Option<usize> {
        let mut i = start + 2;
        while i + 1 < src.len() {
            if src[i] == b'?' && src[i + 1] == b'>' {
                return Some(i + 2);
            }
            i += 1;
        }
        None
    }

    fn find_markup_end(&self, src: &[u8], start: usize) -> Option<usize> {
        if start + 3 < src.len() && &src[start..start + 4] == b"<!--" {
            return self.find_comment_end(src, start + 4);
        }
        if start + 8 < src.len() && &src[start..start + 9] == b"<![CDATA[" {
            return self.find_cdata_end(src, start + 9);
        }
        let mut i = start;
        while i < src.len() {
            if src[i] == b'>' {
                return Some(i + 1);
            }
            i += 1;
        }
        None
    }

    fn find_comment_end(&self, src: &[u8], start: usize) -> Option<usize> {
        let mut i = start;
        while i + 2 < src.len() {
            if &src[i..i + 3] == b"-->" {
                return Some(i + 3);
            }
            i += 1;
        }
        None
    }

    fn find_cdata_end(&self, src: &[u8], start: usize) -> Option<usize> {
        let mut i = start;
        while i + 2 < src.len() {
            if &src[i..i + 3] == b"]]>" {
                return Some(i + 3);
            }
            i += 1;
        }
        None
    }

    fn skip_quoted(&self, src: &[u8], start: usize, quote: u8) -> Option<usize> {
        let mut i = start + 1;
        while i < src.len() {
            if src[i] == quote {
                return Some(i + 1);
            }
            i += 1;
        }
        None
    }
}

impl Decoder for XmlStreamCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        if src.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xml frame too large",
            ));
        }

        let initial_depth = self.depth;
        if let Some(end) = self.find_element_end(src) {
            // Explicitly reset depth after emitting a complete message.
            // find_element_end returns Some only when depth reaches 0,
            // but resetting defensively prevents any future parser change
            // from leaking depth state into the next message.
            self.depth = 0;
            Ok(Some(src.split_to(end)))
        } else {
            // Reject streams with pathological nesting depth
            if self.depth > MAX_XML_DEPTH {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "XML nesting depth limit exceeded",
                ));
            }
            self.depth = initial_depth;
            Ok(None)
        }
    }
}

impl Encoder<BytesMut> for XmlStreamCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len());
        dst.extend_from_slice(&item);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct LineDelimitedCodec;

impl LineDelimitedCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for LineDelimitedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }

        if let Some(pos) = src.iter().position(|&b| b == b'\n') {
            let mut line = src.split_to(pos + 1);
            line.truncate(pos);
            if pos > 0 && line[pos - 1] == b'\r' {
                line.truncate(pos - 1);
            }
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<BytesMut> for LineDelimitedCodec {
    type Error = io::Error;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len() + 1);
        dst.extend_from_slice(&item);
        dst.put_u8(b'\n');
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── VarintDelimitedCodec ────────────────────────────────────────

    /// Encode `len` as a base-128 varint (test helper mirroring the wire).
    fn varint(mut len: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (len & 0x7F) as u8;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if len == 0 {
                break;
            }
        }
        out
    }

    #[test]
    fn varint_decodes_single_frame() {
        let mut codec = VarintDelimitedCodec::new();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&varint(3));
        buf.extend_from_slice(b"abc");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"abc");
        assert!(buf.is_empty());
        // Buffer drained → next decode needs more bytes.
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn varint_decodes_back_to_back_frames() {
        let mut codec = VarintDelimitedCodec::new();
        let mut buf = BytesMut::new();
        for body in [&b"one"[..], &b"twotwo"[..], &b"3"[..]] {
            buf.extend_from_slice(&varint(body.len() as u64));
            buf.extend_from_slice(body);
        }
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"one");
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"twotwo");
        assert_eq!(&codec.decode(&mut buf).unwrap().unwrap()[..], b"3");
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn varint_waits_for_partial_prefix_and_body() {
        let mut codec = VarintDelimitedCodec::new();
        // Frame body is 200 bytes → 2-byte varint prefix (0xC8 0x01).
        let body = [0x5Au8; 200];
        let mut buf = BytesMut::new();
        // Only the first prefix byte (continuation set) → incomplete.
        buf.extend_from_slice(&[0xC8]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // Complete the prefix + partial body → still incomplete.
        buf.extend_from_slice(&[0x01]);
        buf.extend_from_slice(&body[..100]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // Deliver the rest → one full frame.
        buf.extend_from_slice(&body[100..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().len(), 200);
    }

    #[test]
    fn varint_rejects_oversized_length_before_allocating() {
        let mut codec = VarintDelimitedCodec::new().with_max_frame_size(16);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&varint(17)); // one over the cap
        buf.extend_from_slice(&[0u8; 4]); // only a few body bytes present
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn varint_rejects_non_terminating_prefix() {
        let mut codec = VarintDelimitedCodec::new();
        let mut buf = BytesMut::new();
        // 11 continuation bytes — never terminates within the 10-byte cap.
        buf.extend_from_slice(&[0x80u8; 11]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn varint_encode_decode_round_trip() {
        let mut codec = VarintDelimitedCodec::new();
        let mut wire = BytesMut::new();
        let payload = BytesMut::from(&b"round-trip-payload"[..]);
        codec.encode(payload.clone(), &mut wire).unwrap();
        let decoded = codec.decode(&mut wire).unwrap().unwrap();
        assert_eq!(decoded, payload);
    }

    // ── HeaderLengthCodec (Link 16 JREAP-C shape: 16B header, u32 @ 12) ──

    /// Build a JREAP-C-shaped frame: 16-byte header (body_length u32 BE at
    /// offset 12) + `body`.
    fn jreap_frame(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 16];
        out[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn header_length_yields_full_frame_including_header() {
        let mut codec = HeaderLengthCodec::new(16, 12, HeaderSize::Four);
        let mut buf = BytesMut::from(jreap_frame(b"abcd").as_slice());
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        // The yielded frame includes the 16-byte header + 4-byte body.
        assert_eq!(frame.len(), 20);
        assert_eq!(&frame[16..], b"abcd");
        assert!(buf.is_empty());
    }

    #[test]
    fn header_length_waits_for_header_then_body() {
        let mut codec = HeaderLengthCodec::new(16, 12, HeaderSize::Four);
        let wire = jreap_frame(b"hello-world");
        let mut buf = BytesMut::new();
        // Partial header → None.
        buf.extend_from_slice(&wire[..10]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // Full header but partial body → None.
        buf.extend_from_slice(&wire[10..20]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // Rest of the body → one full frame.
        buf.extend_from_slice(&wire[20..]);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().len(), 16 + 11);
    }

    #[test]
    fn header_length_rejects_oversized_body_before_allocating() {
        let mut codec = HeaderLengthCodec::new(16, 12, HeaderSize::Four).with_max_frame_size(8);
        let mut buf = BytesMut::from(jreap_frame(&[0u8; 9]).as_slice()); // body 9 > cap 8
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn header_length_rejects_length_field_past_header() {
        // SEC-8: offset 12 + 4-byte length = 16 > 8-byte header. Before the
        // fix this indexed out of bounds in `read_body_length` and panicked
        // the task; now it must surface InvalidData.
        let mut codec = HeaderLengthCodec::new(8, 12, HeaderSize::Four);
        let mut buf = BytesMut::from(&[0u8; 8][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("header"));
    }

    #[test]
    fn header_length_rejects_length_field_one_byte_past_header() {
        // SEC-8: 12 + 4 = 16 > 15 — the bound is `>`, so a field ending one
        // byte past the header is still rejected.
        let mut codec = HeaderLengthCodec::new(15, 12, HeaderSize::Four);
        let mut buf = BytesMut::from(&[0u8; 15][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn header_length_accepts_length_field_flush_with_header_end() {
        // SEC-8: 12 + 4 = 16 == 16 — the field fits exactly and must decode
        // normally (the bound is inclusive at the header boundary).
        let mut codec = HeaderLengthCodec::new(16, 12, HeaderSize::Four);
        let mut buf = BytesMut::from(jreap_frame(b"abcd").as_slice());
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.len(), 20);
    }

    #[test]
    fn header_length_rejects_out_of_bounds_for_non_four_width() {
        // SEC-8: the width-aware bound must reject a too-wide field for
        // every HeaderSize, not just Four. offset 1 + 2-byte field = 3 > 2.
        let mut codec = HeaderLengthCodec::new(2, 1, HeaderSize::Two);
        let mut buf = BytesMut::from(&[0u8; 2][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn header_length_encode_is_unsupported() {
        let mut codec = HeaderLengthCodec::new(16, 12, HeaderSize::Four);
        let mut dst = BytesMut::new();
        let err = codec
            .encode(BytesMut::from(&b"x"[..]), &mut dst)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    // ── XmlStreamCodec ──────────────────────────────────────────────

    #[test]
    fn xml_basic_element() {
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::from("<event><detail/></event>");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, "<event><detail/></event>");
        assert!(buf.is_empty());
    }

    #[test]
    fn xml_self_closing_tag() {
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::from(r#"<point lat="0" lon="0"/>"#);
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, r#"<point lat="0" lon="0"/>"#);
    }

    #[test]
    fn xml_nested_elements() {
        let mut codec = XmlStreamCodec::new();
        let xml = "<event><point/><detail><status battery=\"100\"/></detail></event>";
        let mut buf = BytesMut::from(xml);
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, xml);
        assert!(buf.is_empty());
    }

    #[test]
    fn xml_partial_frame_buffers() {
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::from("<event><detail/>");
        // Incomplete — missing </event>
        assert!(
            codec
                .decode(&mut buf)
                .expect("decode should succeed")
                .is_none()
        );
        // Now complete it
        buf.extend_from_slice(b"</event>");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, "<event><detail/></event>");
    }

    #[test]
    fn xml_declaration_before_element() {
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::from("<?xml version=\"1.0\"?><event/>");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        // PI is consumed as part of the scan, element follows
        assert_eq!(frame, "<?xml version=\"1.0\"?><event/>");
    }

    #[test]
    fn xml_cdata_preserved() {
        let mut codec = XmlStreamCodec::new();
        let xml = "<detail><![CDATA[raw > data & more]]></detail>";
        let mut buf = BytesMut::from(xml);
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, xml);
    }

    #[test]
    fn xml_comment_handling() {
        let mut codec = XmlStreamCodec::new();
        let xml = "<!-- comment --><event/>";
        let mut buf = BytesMut::from(xml);
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, xml);
    }

    #[test]
    fn xml_comment_inside_element() {
        let mut codec = XmlStreamCodec::new();
        let xml = "<event><!-- inner --><detail/></event>";
        let mut buf = BytesMut::from(xml);
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, xml);
    }

    #[test]
    fn xml_max_depth_enforcement() {
        let mut codec = XmlStreamCodec::new();
        // Build 257 nested opening tags without any closing tags.
        // Exceeds MAX_XML_DEPTH (256).
        let mut xml = String::new();
        for _ in 0..=MAX_XML_DEPTH {
            xml.push_str("<a>");
        }
        let mut buf = BytesMut::from(xml.as_str());
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.expect_err("should be an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("depth"),
            "error should mention depth: {err}"
        );
    }

    #[test]
    fn xml_max_frame_size_enforcement() {
        let mut codec = XmlStreamCodec::new();
        // Buffer exceeding 16 MB
        let oversized = vec![b'<'; MAX_FRAME_SIZE + 1];
        let mut buf = BytesMut::from(oversized.as_slice());
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.expect_err("should be an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn xml_quoted_attributes_with_angle_brackets() {
        let mut codec = XmlStreamCodec::new();
        // Quoted attribute containing > should not end the tag
        let xml = r#"<event attr="val>ue"><detail/></event>"#;
        let mut buf = BytesMut::from(xml);
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, xml);
    }

    #[test]
    fn xml_consecutive_elements() {
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::from("<first/><second/>");
        let frame1 = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce first frame");
        assert_eq!(frame1, "<first/>");
        let frame2 = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce second frame");
        assert_eq!(frame2, "<second/>");
        assert!(buf.is_empty());
    }

    /// Depth counter must be zero after emitting a complete message, so
    /// the next message in the stream is not rejected as "too deep."
    #[test]
    fn xml_depth_resets_between_messages() {
        let mut codec = XmlStreamCodec::new();
        // First message: deeply nested but valid.
        let msg1 = "<a><b><c><d>x</d></c></b></a>";
        // Second message: simple self-closing root.
        let msg2 = "<event/>";
        let mut buf = BytesMut::from(format!("{msg1}{msg2}").as_str());

        let frame1 = codec
            .decode(&mut buf)
            .expect("decode first should succeed")
            .expect("should produce first frame");
        assert_eq!(frame1, msg1);

        // If depth leaked from the first message, this would fail.
        let frame2 = codec
            .decode(&mut buf)
            .expect("decode second should succeed")
            .expect("should produce second frame");
        assert_eq!(frame2, msg2);
    }

    #[test]
    fn xml_encode_is_passthrough() {
        let mut codec = XmlStreamCodec::new();
        let data = BytesMut::from("<event/>");
        let mut dst = BytesMut::new();
        codec.encode(data, &mut dst).expect("encode should succeed");
        assert_eq!(dst, "<event/>");
    }

    #[test]
    fn xml_empty_buffer_returns_none() {
        let mut codec = XmlStreamCodec::new();
        let mut buf = BytesMut::new();
        assert!(
            codec
                .decode(&mut buf)
                .expect("decode should succeed")
                .is_none()
        );
    }

    // ── LineDelimitedCodec ──────────────────────────────────────────

    #[test]
    fn line_lf_terminated() {
        let mut codec = LineDelimitedCodec::new();
        let mut buf = BytesMut::from("hello\n");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, "hello");
    }

    #[test]
    fn line_crlf_terminated() {
        let mut codec = LineDelimitedCodec::new();
        let mut buf = BytesMut::from("hello\r\n");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert_eq!(frame, "hello");
    }

    #[test]
    fn line_empty_line() {
        let mut codec = LineDelimitedCodec::new();
        let mut buf = BytesMut::from("\n");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert!(frame.is_empty());
    }

    #[test]
    fn line_no_terminator_buffers() {
        let mut codec = LineDelimitedCodec::new();
        let mut buf = BytesMut::from("partial");
        assert!(
            codec
                .decode(&mut buf)
                .expect("decode should succeed")
                .is_none()
        );
        // Data remains in buffer
        assert_eq!(buf, "partial");
    }

    #[test]
    fn line_max_frame_size_enforcement() {
        let mut codec = LineDelimitedCodec::new();
        // Buffer exceeding 16 MB with no newline
        let oversized = vec![b'x'; MAX_FRAME_SIZE + 1];
        let mut buf = BytesMut::from(oversized.as_slice());
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.expect_err("should be an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn line_encode_appends_newline() {
        let mut codec = LineDelimitedCodec::new();
        let data = BytesMut::from("hello");
        let mut dst = BytesMut::new();
        codec.encode(data, &mut dst).expect("encode should succeed");
        assert_eq!(dst, "hello\n");
    }

    #[test]
    fn line_consecutive_lines() {
        let mut codec = LineDelimitedCodec::new();
        let mut buf = BytesMut::from("first\nsecond\n");
        let frame1 = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce first frame");
        assert_eq!(frame1, "first");
        let frame2 = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce second frame");
        assert_eq!(frame2, "second");
        assert!(buf.is_empty());
    }

    #[test]
    fn line_empty_crlf() {
        let mut codec = LineDelimitedCodec::new();
        let mut buf = BytesMut::from("\r\n");
        let frame = codec
            .decode(&mut buf)
            .expect("decode should succeed")
            .expect("should produce a frame");
        assert!(frame.is_empty());
    }

    // ── FramedCodec::try_from_strategy ──────────────────────────────

    /// Strategies that do not depend on a cargo feature must always
    /// construct successfully, regardless of how the crate was built.
    #[test]
    fn try_from_strategy_always_available_variants_succeed() {
        for strategy in [
            FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::One,
            },
            FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Two,
            },
            FramingStrategy::LengthPrefixed {
                header_size: HeaderSize::Four,
            },
            FramingStrategy::XmlStream,
            FramingStrategy::LineDelimited,
        ] {
            assert!(
                FramedCodec::try_from_strategy(&strategy).is_ok(),
                "unconditional strategy {strategy:?} must always construct"
            );
        }
    }

    /// When built without the `proto` feature, asking for the TAK
    /// protobuf strategy returns `FeatureNotEnabled { feature: "proto" }`
    /// rather than panicking / aborting (release profile is `panic = "abort"`).
    #[cfg(not(feature = "proto"))]
    #[test]
    fn try_from_strategy_rejects_protobuf_without_feature() {
        let err = FramedCodec::try_from_strategy(&FramingStrategy::TakProtobuf)
            .expect_err("TakProtobuf without `proto` feature must be a structured error");
        match err {
            FramedCodecError::FeatureNotEnabled { feature } => {
                assert_eq!(feature, "proto");
            }
        }
    }

    /// When built without the `mavlink` feature, asking for the
    /// MAVLink strategy returns `FeatureNotEnabled { feature: "mavlink" }`.
    #[cfg(not(feature = "mavlink"))]
    #[test]
    fn try_from_strategy_rejects_mavlink_without_feature() {
        let err = FramedCodec::try_from_strategy(&FramingStrategy::Mavlink)
            .expect_err("Mavlink without `mavlink` feature must be a structured error");
        match err {
            FramedCodecError::FeatureNotEnabled { feature } => {
                assert_eq!(feature, "mavlink");
            }
        }
    }

    /// `FramedCodecError` converts into `io::Error` with
    /// `ErrorKind::InvalidInput` so call sites can propagate via `?`.
    #[test]
    fn framed_codec_error_is_invalid_input_io_error() {
        let err = FramedCodecError::FeatureNotEnabled { feature: "proto" };
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
        let rendered = io_err.to_string();
        assert!(
            rendered.contains("proto"),
            "io::Error message must name the disabled feature, got: {rendered}"
        );
    }
}
