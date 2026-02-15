/// Describes how to detect message boundaries on a byte stream.
#[derive(Debug, Clone)]
pub enum FramingStrategy {
    /// First N bytes encode the message length.
    LengthPrefixed { header_size: HeaderSize },
    /// Read until an XML closing tag.
    XmlStream,
    /// Newline-delimited messages.
    LineDelimited,
}

/// Valid header sizes for length-prefixed framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSize {
    One,
    Two,
    Four,
}

impl HeaderSize {
    pub fn byte_count(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}
