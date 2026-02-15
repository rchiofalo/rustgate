//! Message framing codecs.

use std::io;

use rustgate_core::protocol::FramingStrategy;
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

#[derive(Debug)]
pub enum FramedCodec {
    LengthPrefixed(LengthPrefixedCodec),
    XmlStream(XmlStreamCodec),
    LineDelimited(LineDelimitedCodec),
}

impl FramedCodec {
    pub fn from_strategy(strategy: &FramingStrategy) -> Self {
        match strategy {
            FramingStrategy::LengthPrefixed { header_bytes } => {
                Self::LengthPrefixed(LengthPrefixedCodec::new(*header_bytes))
            }
            FramingStrategy::XmlStream => Self::XmlStream(XmlStreamCodec::new()),
            FramingStrategy::LineDelimited => Self::LineDelimited(LineDelimitedCodec::new()),
        }
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
        }
    }
}

#[derive(Debug, Clone)]
pub struct LengthPrefixedCodec {
    header_bytes: usize,
    pending_len: Option<usize>,
}

#[derive(Debug, Default)]
pub struct XmlStreamCodec {
    depth: usize,
}

impl LengthPrefixedCodec {
    pub fn new(header_bytes: usize) -> Self {
        assert!(header_bytes == 1 || header_bytes == 2 || header_bytes == 4);
        Self {
            header_bytes,
            pending_len: None,
        }
    }

    fn read_length(&self, src: &[u8]) -> usize {
        match self.header_bytes {
            1 => src[0] as usize,
            2 => u16::from_be_bytes([src[0], src[1]]) as usize,
            4 => u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize,
            _ => unreachable!(),
        }
    }

    fn write_length(&self, len: usize, dst: &mut BytesMut) {
        match self.header_bytes {
            1 => dst.put_u8(len as u8),
            2 => dst.put_u16(len as u16),
            4 => dst.put_u32(len as u32),
            _ => unreachable!(),
        }
    }

    fn max_payload_size(&self) -> usize {
        let header_max = match self.header_bytes {
            1 => u8::MAX as usize,
            2 => u16::MAX as usize,
            4 => u32::MAX as usize,
            _ => unreachable!(),
        };
        header_max.min(MAX_FRAME_SIZE)
    }
}

impl Decoder for LengthPrefixedCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let payload_len = match self.pending_len {
            Some(len) => len,
            None => {
                if src.len() < self.header_bytes {
                    return Ok(None);
                }
                let len = self.read_length(&src[..self.header_bytes]);
                if len > MAX_FRAME_SIZE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
                }
                src.advance(self.header_bytes);
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
        dst.reserve(self.header_bytes + item.len());
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
            return Err(io::Error::new(io::ErrorKind::InvalidData, "xml frame too large"));
        }

        let initial_depth = self.depth;
        if let Some(end) = self.find_element_end(src) {
            Ok(Some(src.split_to(end)))
        } else {
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
