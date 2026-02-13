/// Describes how to detect message boundaries on a byte stream.
#[derive(Debug, Clone)]
pub enum FramingStrategy {
    /// First N bytes encode the message length.
    LengthPrefixed { header_bytes: usize },
    /// Read until an XML closing tag.
    XmlStream,
    /// Newline-delimited messages.
    LineDelimited,
}

/// Metadata about a registered protocol handler.
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    pub id: String,
    pub name: &'static str,
    pub default_port: u16,
    pub framing: FramingStrategy,
}
