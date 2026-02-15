//! Message framing codecs.

use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub struct LengthPrefixedCodec {
    header_bytes: usize,
}

#[derive(Debug)]
pub struct XmlStreamCodec;

impl LengthPrefixedCodec {
    pub fn new(header_bytes: usize) -> Self {
        Self { header_bytes }
    }
}

impl Decoder for LengthPrefixedCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        todo!()
    }
}

impl Encoder<BytesMut> for LengthPrefixedCodec {
    type Error = std::io::Error;

    fn encode(&mut self, _item: BytesMut, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        todo!()
    }
}

impl Decoder for XmlStreamCodec {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        todo!()
    }
}

impl Encoder<BytesMut> for XmlStreamCodec {
    type Error = std::io::Error;

    fn encode(&mut self, _item: BytesMut, _dst: &mut BytesMut) -> Result<(), Self::Error> {
        todo!()
    }
}
