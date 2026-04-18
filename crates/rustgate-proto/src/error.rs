// Copyright © 2026 Roberto Chiofalo.

//! Protocol translation error types.

/// Errors during TAK protocol buffer translation.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("protobuf decode: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("protobuf encode: {0}")]
    Encode(#[from] prost::EncodeError),

    #[error("xml parse: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },

    /// A numeric field was outside its spec-defined range.
    ///
    /// MITRE CoT Message Router User's Guide (MP090284) Table 2-1 defines
    /// `lat` and `lon` in WGS-84 decimal degrees: latitude -90..=90,
    /// longitude -180..=180.
    #[error("field `{field}` out of range: {value}")]
    OutOfRange { field: &'static str, value: f64 },
}

impl From<ProtoError> for std::io::Error {
    fn from(e: ProtoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}
