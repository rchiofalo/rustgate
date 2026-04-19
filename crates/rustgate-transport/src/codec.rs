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
mod tests {
    use super::*;

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
